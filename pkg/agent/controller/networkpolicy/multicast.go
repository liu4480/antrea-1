package networkpolicy

import (
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/util/channel"
	"fmt"
	"k8s.io/apimachinery/pkg/util/sets"
	"net"
	"sync"
	"time"

	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	crdv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type ruleType int
type eventType uint8
const (
	unicast   ruleType = 0
	igmp      ruleType = 1
	multicast ruleType = 2

	groupJoin eventType = iota
	groupLeave
	rulechanged
)

var (
	mcastAllHosts      = net.ParseIP("224.0.0.1").To4()
	_, mcastAllHostsCIDR, _  = net.ParseCIDR("224.0.0.1/32")
)

type mcastItem struct {
	groupAddress net.IPNet
	ruleIDs map[string]*uint16
}

type GroupMemberStatus struct {
	group net.IP
	// localMembers is a map for the local Pod member and its last update time, key is the Pod's interface name,
	// and value is its last update time.
	localMembers   map[string]time.Time
	lastIGMPReport time.Time
	mutex          sync.RWMutex
	ofGroupID      binding.GroupIDType
}

type mcastGroupEvent struct {
	eType eventType
	iface *interfacestore.InterfaceConfig
}

type multicastController struct {
	ofClient     openflow.Client

	ifaceStore  interfacestore.InterfaceStore

	queryGroupId         binding.GroupIDType
	groupInstalled       bool
	queryGroupStatus     GroupMemberStatus

	ruleCache            *ruleCache
	mcastItemRuleIDMap   map[string]mcastItem
	mcastItemMutex       sync.RWMutex
	ruleIDGroupAddressMap map[string]sets.String
	ruleIDGroupMapMutex sync.RWMutex
	eventCh             chan mcastGroupEvent
}

func (c *multicastController) syncQueryGroup(stopCh <- chan struct{}) {
	for  {
		select  {
		case event := <- c.eventCh:
			klog.Info("resync query group")
			if c.queryGroupId == 0 {
				klog.Infof("c.queryGroupId == 0 %v", c.queryGroupId == 0)
				return
			}
			now := time.Now()
			if event.eType == groupJoin {
				if event.iface != nil {
					c.queryGroupStatus.mutex.Lock()
					c.queryGroupStatus.localMembers[event.iface.InterfaceName] = now
					c.queryGroupStatus.mutex.Unlock()
					c.queryGroupStatus.lastIGMPReport = now
					if len(c.queryGroupStatus.localMembers) > 0 {
						err := c.updateGroup()
						if err != nil {
							klog.Errorf("failed to update query group: %+v", err)
						}
					} else {
						klog.Infof("no member in query group: %+v", c.queryGroupStatus.localMembers)
					}
				}
			} else if event.eType == groupLeave {
				c.queryGroupStatus.mutex.Lock()
				delete(c.queryGroupStatus.localMembers, event.iface.InterfaceName)
				c.queryGroupStatus.mutex.Unlock()
				c.queryGroupStatus.lastIGMPReport = now
				if len(c.queryGroupStatus.localMembers) > 0 {
					err := c.updateGroup()
					if err != nil {
						klog.Errorf("failed to update query group: %+v", err)
					}
				} else {
					klog.V(2).InfoS("no member in query group: ", c.queryGroupStatus.localMembers)
				}
			} else if event.eType == rulechanged {
				if len(c.queryGroupStatus.localMembers) > 0 {
					err := c.updateGroup()
					if err != nil {
						klog.Errorf("failed to update query group: %+v", err)
					}
				} else {
					klog.V(2).InfoS("no member in query group: ", c.queryGroupStatus.localMembers)
				}
			}
		case <-stopCh:
			return
		}
	}
}

func (c *multicastController) groupIsStale() bool {
	return false
}

func (c *multicastController) groupHasInstalled() bool {
	return c.groupInstalled
}

func (c *multicastController) updateGroup() error {
	groupKey := mcastAllHosts.String()
	c.queryGroupStatus.mutex.Lock()
	defer c.queryGroupStatus.mutex.Unlock()
	memberPorts := make([]uint32, 0)
	blocked_ports := make(map[uint32]bool)
	for memberInterfaceName := range c.queryGroupStatus.localMembers {
		obj, found := c.ifaceStore.GetInterfaceByName(memberInterfaceName)
		if !found {
			klog.InfoS("Failed to find interface from cache", "interface", memberInterfaceName)
			continue
		}
		action, _, name, _ := c.validation(obj, *mcastAllHostsCIDR, crdv1beta.DirectionIn)
		if name != "" && (*action == v1alpha1.RuleActionDrop) {
			klog.V(4).Infof("policy will block ofport: %d, pod: %s/%s", obj.OFPort, obj.PodNamespace, obj.PodName)
			blocked_ports[uint32(obj.OFPort)] = true
		}
		memberPorts = append(memberPorts, uint32(obj.OFPort))
	}
	if c.groupHasInstalled() {
		if c.groupIsStale() {
			// Remove the multicast flow entry if no local Pod is in the group.
			if err := c.ofClient.UninstallMulticastFlows(c.queryGroupStatus.group); err != nil {
				klog.ErrorS(err, "Failed to uninstall multicast flows", "group", groupKey)
				return err
			}
			// Remove the multicast flow entry if no local Pod is in the group.
			if err := c.ofClient.UninstallGroup(c.queryGroupStatus.ofGroupID); err != nil {
				klog.ErrorS(err, "Failed to uninstall multicast group", "group", groupKey)
				return err
			}

			c.groupInstalled = false
			klog.InfoS("Removed multicast group from cache after all members left", "group", groupKey)
			return nil
		}
		// Reinstall OpenFlow group because the local pod receivers have changed.
		if err := c.ofClient.InstallIGMPGroup(c.queryGroupStatus.ofGroupID, blocked_ports, true, memberPorts); err != nil {
			return err
		}
		klog.V(2).InfoS("Updated OpenFlow group for local receivers", "group", groupKey, "ofGroup", c.queryGroupStatus.ofGroupID, "localReceivers", memberPorts)
		return nil
	}
	// Install OpenFlow group for a new multicast group which has local Pod receivers joined.
	if err := c.ofClient.InstallIGMPGroup(c.queryGroupId, blocked_ports, true, memberPorts); err != nil {
		return err
	}
	klog.V(2).InfoS("Installed OpenFlow group for local receivers", "group", groupKey, "ofGroup", c.queryGroupStatus.ofGroupID, "localReceivers", memberPorts)
	// Install OpenFlow flow to forward packets to local Pod receivers which are included in the group.
	if err := c.ofClient.InstallMulticastFlows(c.queryGroupStatus.group, c.queryGroupStatus.ofGroupID); err != nil {
		klog.ErrorS(err, "Failed to install multicast flows", "group", c.queryGroupStatus.group)
		return err
	}
	if err := c.ofClient.InstallMulticastIGMPQueryFlow(); err != nil {
		klog.ErrorS(err, "Failed to install igmp query flows", "group", c.queryGroupStatus.group)
		return err
	}
	c.groupInstalled = true
	return nil
}

func (c *multicastController) initialize(cache *ruleCache) bool {
	c.ruleCache = cache
	c.queryGroupStatus = GroupMemberStatus{
		group: mcastAllHosts,
		localMembers: make(map[string]time.Time),
		lastIGMPReport: time.Now(),
		ofGroupID: c.queryGroupId,
	}
	now := time.Now()
	ifaces := c.ifaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	for _, iface := range ifaces {
		c.queryGroupStatus.localMembers[iface.InterfaceName] = now
	}
	c.queryGroupStatus.lastIGMPReport = now
	if len(c.queryGroupStatus.localMembers) > 0 {
		err := c.updateGroup()
		if err != nil {
			klog.Errorf("failed to update query group: %+v", err)
		}
	} else {
		klog.Infof("no member in query group: %+v", c.queryGroupStatus.localMembers)
	}
	return true
}

func (c *multicastController) addGroupAddressForTableIDs (ruleID string, priority *uint16, mcastGroupAddresses []string) {
	c.mcastItemMutex.Lock()
	defer c.mcastItemMutex.Unlock()
	c.ruleIDGroupMapMutex.Lock()
	defer c.ruleIDGroupMapMutex.Unlock()
	mcastGroupAddressSet := sets.String{}
	for _, mcastGroupAddress := range mcastGroupAddresses {
		item, exists := c.mcastItemRuleIDMap[mcastGroupAddress]
		ip, cidr, err := net.ParseCIDR(mcastGroupAddress)
		if err != nil {
			ip = net.ParseIP(mcastGroupAddress)
			cidr = &net.IPNet{}
			cidr.IP = ip
			cidr.Mask = net.CIDRMask(32, 32)
		}
		mcastGroupAddressSet.Insert(mcastGroupAddress)
		if !exists {
			item := mcastItem{
				groupAddress: *cidr,
				ruleIDs: make(map[string]*uint16),
			}
			item.ruleIDs[ruleID] = priority
			c.mcastItemRuleIDMap[mcastGroupAddress] = item
		} else {
			item.ruleIDs[ruleID] = priority
			c.mcastItemRuleIDMap[mcastGroupAddress] = item
		}
	}
	if mcastGroupAddressSet.Len() > 0 {
		c.ruleIDGroupAddressMap[ruleID] = mcastGroupAddressSet
	}
	g := mcastGroupEvent{
		eType: rulechanged,
	}
	c.eventCh <- g
}

func (c *multicastController) updateGroupAddressForTableIDs (ruleID string, priority *uint16, mcastGroupAddresses []string) {
	c.mcastItemMutex.Lock()
	defer c.mcastItemMutex.Unlock()

	c.ruleIDGroupMapMutex.Lock()
	defer c.ruleIDGroupMapMutex.Unlock()

	staleMcastGroupAddresses, ok := c.ruleIDGroupAddressMap[ruleID]
	for _, mcastGroupAddress := range mcastGroupAddresses {
		item, exists := c.mcastItemRuleIDMap[mcastGroupAddress]
		ip, cidr, err := net.ParseCIDR(mcastGroupAddress)
		if err != nil {
			ip = net.ParseIP(mcastGroupAddress)
			cidr = &net.IPNet{}
			cidr.IP = ip
			cidr.Mask = net.CIDRMask(32, 32)
		}
		if !exists {
			item := mcastItem{
				groupAddress: *cidr,
				ruleIDs: make(map[string]*uint16),
			}
			item.ruleIDs[ruleID] = priority
			c.mcastItemRuleIDMap[mcastGroupAddress] = item
		} else {
			item.ruleIDs[ruleID] = priority
			c.mcastItemRuleIDMap[mcastGroupAddress] = item
		}
	}
	if !ok {
		staleMcastGroupAddresses = sets.String{}
	}
	for staleGroupAddress := range staleMcastGroupAddresses {
		if item, ok := c.mcastItemRuleIDMap[staleGroupAddress]; ok {
			if _, ok = item.ruleIDs[ruleID]; ok {
				delete(item.ruleIDs, ruleID)
				if len(item.ruleIDs) > 0 {
					c.mcastItemRuleIDMap[staleGroupAddress] = item
				} else {
					c.cleanupGroupAddressForTableIDsUnlocked(staleGroupAddress)
				}
			}
		}
	}

	newMcastGroupAddresses := sets.String{}
	for _, mcastGroupAddress := range mcastGroupAddresses {
		newMcastGroupAddresses.Insert(mcastGroupAddress)
	}
	c.ruleIDGroupAddressMap[ruleID] = newMcastGroupAddresses
	g := mcastGroupEvent{
		eType: rulechanged,
	}
	c.eventCh <- g
}

func (c *multicastController) deleteGroupAddressForTableIDs (ruleID string, groupAddresses []string) {
	c.mcastItemMutex.Lock()
	defer c.mcastItemMutex.Unlock()
	c.ruleIDGroupMapMutex.Lock()
	defer c.ruleIDGroupMapMutex.Unlock()
	for _, groupAddress := range groupAddresses {
		item, exists := c.mcastItemRuleIDMap[groupAddress]
		klog.V(2).Infof("deleteGroupAddressForTableIDs groupAddress: %v, exist %v, map %+v %+v",
			groupAddress, exists, c.mcastItemRuleIDMap, item)
		if _, ok := item.ruleIDs[ruleID]; exists && ok {
			delete(item.ruleIDs, ruleID)
			if len(item.ruleIDs) > 0 {
				c.mcastItemRuleIDMap[groupAddress] = item
			} else {
				c.cleanupGroupAddressForTableIDsUnlocked(groupAddress)
			}
		}
		klog.V(2).Infof("after deleteGroupAddressForTableIDs groupAddress: %v, exist %v, map %+v %+v",
			groupAddress, exists, c.mcastItemRuleIDMap, item)
	}

	delete(c.ruleIDGroupAddressMap, ruleID)
	g := mcastGroupEvent{
		eType: rulechanged,
	}
	c.eventCh <- g
}

// cleanupFQDNSelectorItem handles a fqdnSelectorItem delete event.
func (c *multicastController) cleanupGroupAddressForTableIDsUnlocked (groupAddress string) {
	_, exists := c.mcastItemRuleIDMap[groupAddress]
	if exists {
		delete(c.mcastItemRuleIDMap, groupAddress)
	}
}

func (c *multicastController) validation(iface *interfacestore.InterfaceConfig,
	groupAddress net.IPNet, direction crdv1beta.Direction) (*v1alpha1.RuleAction, apitypes.UID, string, error) {
	action, uuid, ruleName := v1alpha1.RuleActionDrop, apitypes.UID("0"), ""
	if iface == nil {
		//check the whole group
		klog.Info("Iface should not be empty")
		return nil, apitypes.UID(""), "", fmt.Errorf("iface should not be empty")
	}
	ns, podname := iface.PodNamespace, iface.PodName
	c.mcastItemMutex.Lock()
	defer c.mcastItemMutex.Unlock()
	item, exists := c.mcastItemRuleIDMap[groupAddress.String()]
	if !exists {
		item, exists = c.mcastItemRuleIDMap[groupAddress.IP.String()]
		if !exists {
			klog.V(2).Infof("rule for group %s does not exist: %+v", groupAddress.String(), c.mcastItemRuleIDMap)
			action = v1alpha1.RuleActionAllow
			return &action, apitypes.UID(""), "", nil
		}
	}
	var matchedRule *CompletedRule
	for ruleID := range item.ruleIDs {
		rule, _, _ := c.ruleCache.GetCompletedRule(ruleID)
		member := &crdv1beta.GroupMember{
			Pod: &crdv1beta.PodReference {
				Name: podname,
				Namespace: ns,
			},
		}

		if (matchedRule == nil) || *(item.ruleIDs[ruleID]) > *(item.ruleIDs[matchedRule.ID]) {
			if rule.Direction == crdv1beta.DirectionIn && direction == rule.Direction{
				if rule.TargetMembers.Has(member) == true {
					matchedRule = rule
				}
			} else if rule.Direction == crdv1beta.DirectionOut && direction == rule.Direction{
				if rule.TargetMembers.Has(member) == true {
					matchedRule = rule
				}
			}
		}
	}
	if matchedRule != nil {
		action, uuid, ruleName = *matchedRule.Action, matchedRule.PolicyUID, matchedRule.Name
	} else {
		action, uuid, ruleName = v1alpha1.RuleActionAllow, apitypes.UID(""), ""
	}
	klog.V(4).Infof("validation: action %v, uuid %v, ruleName %v, found %v",
		action, uuid, ruleName)
	return &action, uuid, ruleName, nil
}

func (c *multicastController) run(stopCh <- chan struct{}) {
	go c.syncQueryGroup(stopCh)
}

func (c *multicastController) memberChanged(e interface{}) {
	podEvent := e.(types.PodUpdate)
	namespace, name := podEvent.PodNamespace, podEvent.PodName
	containerID := podEvent.ContainerID
	interfaceName := util.GenerateContainerInterfaceName(name, namespace, containerID)
	iface, ok := c.ifaceStore.GetInterfaceByName(interfaceName)
	klog.Infof("memberChanged: %+v", podEvent.IsAdd)
	if podEvent.IsAdd {
		if ok {
			g := mcastGroupEvent{
				eType: groupJoin,
				iface: iface,
			}
			c.eventCh <- g
		}
	} else {
		if ok {
			g := mcastGroupEvent{
				eType: groupLeave,
				iface: iface,
			}
			c.eventCh <- g
		}
	}
}

func NewMulticastNetworkPolicyController(ofClient openflow.Client,
							ifaceStore interfacestore.InterfaceStore,
							podUpdateSubscriber channel.Subscriber,
							queryGroupID binding.GroupIDType) (*multicastController, error) {
	mcastController := &multicastController{
		ofClient: ofClient,
		ifaceStore: ifaceStore,
		groupInstalled: false,
		mcastItemRuleIDMap: make(map[string]mcastItem),
		ruleIDGroupAddressMap: make(map[string]sets.String),
		queryGroupId: queryGroupID,
		eventCh: make(chan mcastGroupEvent),
	}
	klog.Infof("podUpdateSubscriber.Subscribe(mcastController.memberChanged)")
	podUpdateSubscriber.Subscribe(mcastController.memberChanged)
	return mcastController, nil
}

func (m *multicastController) Validation (iface *interfacestore.InterfaceConfig, groupAddress net.IP) (*v1alpha1.RuleAction, apitypes.UID, string, error) {
	groupAddressCidr := net.IPNet{
							IP: groupAddress,
							Mask: net.CIDRMask(32,32),
						}
	return m.validation(iface, groupAddressCidr, crdv1beta.DirectionOut)
}