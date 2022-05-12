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
	crdv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

type ruleType int

const (
	unicast   ruleType = 0
	igmp      ruleType = 1
	multicast ruleType = 2
)

type mcastItem struct {
	groupAddress net.IPNet
	ruleIDs      map[string]*uint16
}

type multicastController struct {
	ofClient openflow.Client

	ifaceStore interfacestore.InterfaceStore
	ruleCache  *ruleCache
	//key is multicast groupAddress, while value is map for ruleID:priority
	mcastItemRuleIDMap map[string]mcastItem
	mcastItemMutex     sync.RWMutex
	//key is ruleID while the value is list of group addresses
	ruleIDGroupAddressMap map[string]sets.String
	ruleIDGroupMapMutex   sync.RWMutex
}

func (c *multicastController) addGroupAddressForTableIDs(ruleID string, priority *uint16, mcastGroupAddresses []string) {
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
		c.ruleIDGroupAddressMap[ruleID] = mcastGroupAddressSet
	}
}

func (c *multicastController) updateGroupAddressForTableIDs(ruleID string, priority *uint16, mcastGroupAddresses []string) {
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
}

func (c *multicastController) deleteGroupAddressForTableIDs(ruleID string, groupAddresses []string) {
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
}

func (c *multicastController) cleanupGroupAddressForTableIDsUnlocked(groupAddress string) {
	_, exists := c.mcastItemRuleIDMap[groupAddress]
	if exists {
		delete(c.mcastItemRuleIDMap, groupAddress)
	}
}

func (c *multicastController) validation(iface *interfacestore.InterfaceConfig,
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

func (c *multicastController) run(stopCh <-chan struct{}) {
	//go c.syncQueryGroup(stopCh)
}

func newMulticastNetworkPolicyController(ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore,
	cache *ruleCache) (*multicastController, error) {
	mcastController := &multicastController{
		ofClient:              ofClient,
		ifaceStore:            ifaceStore,
		ruleCache:             cache,
		mcastItemRuleIDMap:    make(map[string]mcastItem),
		ruleIDGroupAddressMap: make(map[string]sets.String),
	}
	return mcastController, nil
}

func (c *multicastController) Validation(obj interface{}, groupAddress net.IP) (interface{}, error) {
	iface := obj.(*interfacestore.InterfaceConfig)
	groupAddressCidr := net.IPNet{
		IP:   groupAddress,
		Mask: net.CIDRMask(32, 32),
	}

	action, uuid, npType, name, err := c.validation(iface, groupAddressCidr, crdv1beta.DirectionOut)
	ret := types.McastNPValidationItem{
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
