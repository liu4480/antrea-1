package networkpolicy

import (
	"fmt"
	"net"
	"sync"

	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	crdv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/channel"
)

type ruleType int
type eventType uint8

const (
	unicast   ruleType = 0
	igmp      ruleType = 1
	multicast ruleType = 2

	groupJoin   eventType = 0
	groupLeave  eventType = 1
	rulechanged eventType = 2
)

var (
	_, mcastAllHostsCIDR, _ = net.ParseCIDR("224.0.0.1/32")
)

type mcastItem struct {
	groupAddress net.IPNet
	ruleIDs      map[string]*uint16
}

type GroupMemberStatus struct {
	localMembers sets.String
	mutex        sync.RWMutex
}

type mcastGroupEvent struct {
	eType eventType
	iface *interfacestore.InterfaceConfig
}

type MulticastController struct {
	ofClient openflow.Client

	ifaceStore interfacestore.InterfaceStore

	queryGroupId     binding.GroupIDType
	groupInstalled   bool
	queryGroupStatus GroupMemberStatus

	ruleCache *ruleCache
	//key is multicast groupAddress, while value is map for ruleID:priority
	mcastItemRuleIDMap map[string]mcastItem
	mcastItemMutex     sync.RWMutex
	//key is ruleID while the value is list of group addresses
	ruleIDGroupAddressMap map[string]sets.String
	ruleIDGroupMapMutex   sync.RWMutex
	eventCh               chan mcastGroupEvent
}

func (c *MulticastController) syncQueryGroup(stopCh <-chan struct{}) {
	for {
		select {
		case event := <-c.eventCh:
			klog.Info("resync query group")
			if c.queryGroupId == 0 {
				klog.Infof("c.queryGroupId == 0 %v", c.queryGroupId == 0)
				return
			}
			if event.eType == groupJoin {
				if event.iface != nil {
					c.queryGroupStatus.mutex.Lock()
					c.queryGroupStatus.localMembers.Insert(event.iface.InterfaceName)
					c.queryGroupStatus.mutex.Unlock()
					err := c.updateGroup()
					if err != nil {
						klog.Errorf("failed to update query group: %+v", err)
					}
				}
			} else if event.eType == groupLeave {
				c.queryGroupStatus.mutex.Lock()
				c.queryGroupStatus.localMembers.Delete(event.iface.InterfaceName)
				c.queryGroupStatus.mutex.Unlock()
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

func (c *MulticastController) groupHasInstalled() bool {
	return c.groupInstalled
}

func (c *MulticastController) updateGroup() error {
	groupKey := types.McastAllHosts.String()
	c.queryGroupStatus.mutex.Lock()
	defer c.queryGroupStatus.mutex.Unlock()
	memberPorts := make([]uint32, 0)
	blockedPorts := make(map[uint32]bool)
	for memberInterfaceName := range c.queryGroupStatus.localMembers {
		obj, found := c.ifaceStore.GetInterfaceByName(memberInterfaceName)
		if !found {
			klog.InfoS("Failed to find interface from cache", "interface", memberInterfaceName)
			continue
		}
		//*v1alpha1.RuleAction, apitypes.UID, *crdv1beta.NetworkPolicyType, string, error
		action, _, _, name, _ := c.validation(obj, *mcastAllHostsCIDR, crdv1beta.DirectionIn)
		if name != "" && (*action == v1alpha1.RuleActionDrop) {
			klog.V(4).Infof("policy will block ofport: %d, pod: %s/%s", obj.OFPort, obj.PodNamespace, obj.PodName)
			blockedPorts[uint32(obj.OFPort)] = true
		}
		memberPorts = append(memberPorts, uint32(obj.OFPort))
	}
	if c.groupHasInstalled() {
		// Reinstall OpenFlow group because the local pod receivers have changed.
		if err := c.ofClient.InstallIGMPGroup(c.queryGroupId, blockedPorts, true, memberPorts); err != nil {
			return err
		}
		klog.V(2).InfoS("Updated OpenFlow group for local receivers", "group", groupKey, "ofGroup", c.queryGroupId, "localReceivers", memberPorts)
		return nil
	}
	// Install OpenFlow group for a new multicast group which has local Pod receivers joined.
	if err := c.ofClient.InstallIGMPGroup(c.queryGroupId, blockedPorts, true, memberPorts); err != nil {
		return err
	}
	klog.V(2).InfoS("Installed OpenFlow group for local receivers", "group", groupKey, "ofGroup", c.queryGroupId, "localReceivers", memberPorts)
	// Install OpenFlow flow to forward packets to local Pod receivers which are included in the group.
	if err := c.ofClient.InstallMulticastFlows(types.McastAllHosts, c.queryGroupId); err != nil {
		klog.ErrorS(err, "Failed to install multicast flows", "group", types.McastAllHosts)
		return err
	}
	c.groupInstalled = true
	return nil
}

func (c *MulticastController) initialize(cache *ruleCache) bool {
	if cache == nil {
		return false
	}
	c.ruleCache = cache
	c.queryGroupStatus = GroupMemberStatus{
		localMembers: sets.String{},
	}
	ifaces := c.ifaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	for _, iface := range ifaces {
		c.queryGroupStatus.localMembers.Insert(iface.InterfaceName)
	}
	if len(c.queryGroupStatus.localMembers) > 0 {
		err := c.updateGroup()
		if err != nil {
			klog.ErrorS(err, "failed to update query group")
		}
	}
	return true
}

func (c *MulticastController) addGroupAddressForTableIDs(ruleID string, priority *uint16, mcastGroupAddresses []string) {
	c.mcastItemMutex.Lock()
	defer c.mcastItemMutex.Unlock()
	c.ruleIDGroupMapMutex.Lock()
	defer c.ruleIDGroupMapMutex.Unlock()
	mcastGroupAddressSet := sets.String{}
	for _, mcastGroupAddress := range mcastGroupAddresses {
		item, exists := c.mcastItemRuleIDMap[mcastGroupAddress]
		_, cidr, err := net.ParseCIDR(mcastGroupAddress)
		if err != nil {
			ip := net.ParseIP(mcastGroupAddress)
			cidr = &net.IPNet{}
			cidr.IP = ip
			cidr.Mask = net.CIDRMask(32, 32)
		}
		mcastGroupAddressSet.Insert(mcastGroupAddress)
		if !exists {
			item := mcastItem{
				groupAddress: *cidr,
				ruleIDs:      make(map[string]*uint16),
			}
			item.ruleIDs[ruleID] = priority
			c.mcastItemRuleIDMap[mcastGroupAddress] = item
		} else {
			item.ruleIDs[ruleID] = priority
			c.mcastItemRuleIDMap[mcastGroupAddress] = item
		}
	}
	if mcastGroupAddressSet.Len() > 0 {
		fmt.Println(mcastGroupAddressSet)
		c.ruleIDGroupAddressMap[ruleID] = mcastGroupAddressSet
	}
	g := mcastGroupEvent{
		eType: rulechanged,
	}
	c.eventCh <- g
}

func (c *MulticastController) updateGroupAddressForTableIDs(ruleID string, priority *uint16, mcastGroupAddresses []string) {
	c.mcastItemMutex.Lock()
	defer c.mcastItemMutex.Unlock()

	c.ruleIDGroupMapMutex.Lock()
	defer c.ruleIDGroupMapMutex.Unlock()

	staleMcastGroupAddresses, ok := c.ruleIDGroupAddressMap[ruleID]
	for _, mcastGroupAddress := range mcastGroupAddresses {
		item, exists := c.mcastItemRuleIDMap[mcastGroupAddress]
		_, cidr, err := net.ParseCIDR(mcastGroupAddress)
		if err != nil {
			ip := net.ParseIP(mcastGroupAddress)
			cidr = &net.IPNet{}
			cidr.IP = ip
			cidr.Mask = net.CIDRMask(32, 32)
		}
		if !exists {
			item := mcastItem{
				groupAddress: *cidr,
				ruleIDs:      make(map[string]*uint16),
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

func (c *MulticastController) deleteGroupAddressForTableIDs(ruleID string, groupAddresses []string) {
	c.mcastItemMutex.Lock()
	defer c.mcastItemMutex.Unlock()
	c.ruleIDGroupMapMutex.Lock()
	defer c.ruleIDGroupMapMutex.Unlock()
	for _, groupAddress := range groupAddresses {
		item, exists := c.mcastItemRuleIDMap[groupAddress]
		klog.V(2).Infof("deleteGroupAddressForTableIDs groupAddress: %v, exist %v, map %+v %+v",
			groupAddress, exists, c.mcastItemRuleIDMap, item)
		if !exists {
			continue
		}
		if _, ok := item.ruleIDs[ruleID]; ok {
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

func (c *MulticastController) cleanupGroupAddressForTableIDsUnlocked(groupAddress string) {
	_, exists := c.mcastItemRuleIDMap[groupAddress]
	if exists {
		delete(c.mcastItemRuleIDMap, groupAddress)
	}
}

func (c *MulticastController) validation(iface *interfacestore.InterfaceConfig,
	groupAddress net.IPNet, direction crdv1beta.Direction) (*v1alpha1.RuleAction, apitypes.UID, *crdv1beta.NetworkPolicyType, string, error) {
	var ruleTypePtr *crdv1beta.NetworkPolicyType
	action, uuid, ruleName := v1alpha1.RuleActionAllow, apitypes.UID("0"), ""
	if iface == nil {
		//check the whole group
		klog.Info("Iface should not be empty")
		return nil, "", nil, "", fmt.Errorf("iface should not be empty")
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
			return &action, "", nil, "", nil
		}
	}
	var matchedRule *CompletedRule
	for ruleID := range item.ruleIDs {
		rule, _, _ := c.ruleCache.GetCompletedRule(ruleID)
		member := &crdv1beta.GroupMember{
			Pod: &crdv1beta.PodReference{
				Name:      podname,
				Namespace: ns,
			},
		}

		if (matchedRule == nil) || *(item.ruleIDs[ruleID]) > *(item.ruleIDs[matchedRule.ID]) {
			if rule.Direction == crdv1beta.DirectionIn && direction == rule.Direction {
				if rule.TargetMembers.Has(member) == true {
					matchedRule = rule
				}
			} else if rule.Direction == crdv1beta.DirectionOut && direction == rule.Direction {
				if rule.TargetMembers.Has(member) == true {
					matchedRule = rule
				}
			}
		}
	}
	if matchedRule != nil {
		ruleTypePtr = new(crdv1beta.NetworkPolicyType)
		action, uuid, *ruleTypePtr, ruleName = *matchedRule.Action, matchedRule.PolicyUID, matchedRule.SourceRef.Type, matchedRule.Name
	} else {
		action, uuid, ruleName = v1alpha1.RuleActionAllow, "", ""
	}
	klog.V(4).Infof("validation: action %v, uuid %v, ruleName %v, ruleType %v",
		action, uuid, ruleName, ruleTypePtr)
	return &action, uuid, ruleTypePtr, ruleName, nil
}

func (c *MulticastController) run(stopCh <-chan struct{}) {
	go c.syncQueryGroup(stopCh)
}

func (c *MulticastController) memberChanged(e interface{}) {
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
	queryGroupID binding.GroupIDType) (*MulticastController, error) {
	mcastController := &MulticastController{
		ofClient:              ofClient,
		ifaceStore:            ifaceStore,
		groupInstalled:        false,
		mcastItemRuleIDMap:    make(map[string]mcastItem),
		ruleIDGroupAddressMap: make(map[string]sets.String),
		queryGroupId:          queryGroupID,
		eventCh:               make(chan mcastGroupEvent),
	}
	klog.Infof("podUpdateSubscriber.Subscribe(mcastController.memberChanged)")
	if podUpdateSubscriber != nil {
		podUpdateSubscriber.Subscribe(mcastController.memberChanged)
	}
	return mcastController, nil
}

func (c *MulticastController) Validation(iface *interfacestore.InterfaceConfig, groupAddress net.IP) (interface{}, error) {
	groupAddressCidr := net.IPNet{
		IP:   groupAddress,
		Mask: net.CIDRMask(32, 32),
	}

	action, uuid, npType, name, err := c.validation(iface, groupAddressCidr, crdv1beta.DirectionOut)
	ret := types.MulticastNPValidation{
		RuleAction: action,
		Uuid:       uuid,
		NPType:     npType,
		Name:       name,
	}
	if err != nil {
		return nil, err
	}
	return ret, nil
}
