// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networkpolicy

import (
	"fmt"
	"net"
	"sync"

	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	crdv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/util/ip"
)

type ruleType int

type ruleEvent uint8

const (
	unicast   ruleType = 0
	igmp      ruleType = 1
	multicast ruleType = 2

	ruleAdd    ruleEvent = 1
	ruleUpdate ruleEvent = 2
	ruleDelete ruleEvent = 3

	groupAddressIndex = "groupAddressIndex"
)

type mcastItem struct {
	groupAddress net.IPNet
	ruleIDs      map[string]*uint16
}

type mcastIGMPRule struct {
	ruleID       string
	priority     *uint16
	groupAddress []string
	event        ruleEvent
}

// multicastController handles only IGMP protocol. It stores the group address to RuleID map and
// also rule to group addresses map
type multicastController struct {
	ofClient openflow.Client

	ifaceStore interfacestore.InterfaceStore
	ruleCache  *ruleCache
	queue      workqueue.RateLimitingInterface
	// key is the multicast group address.
	mcastItemRuleCache cache.Indexer

	// key is ruleID while the value is list of group addresses.
	ruleIDGroupAddressMap map[string]sets.String
	ruleIDGroupMapMutex   sync.RWMutex
}

func groupAddressKey(obj interface{}) (string, error) {
	group := obj.(*mcastItem)
	return group.groupAddress.IP.String(), nil
}

func groupAddressRuleIndexFunc(obj interface{}) ([]string, error) {
	item := obj.(*mcastItem)
	ruleIDs := make([]string, len(item.ruleIDs))
	for ruleID := range item.ruleIDs {
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs, nil
}

func (c *multicastController) addGroupAddressForTableIDs(ruleID string, priority *uint16, mcastGroupAddresses []string) {
	igmpRule := &mcastIGMPRule{
		ruleID:       ruleID,
		priority:     priority,
		groupAddress: mcastGroupAddresses,
		event:        ruleAdd,
	}
	c.queue.Add(igmpRule)
}

func (c *multicastController) updateGroupAddressForTableIDs(ruleID string, priority *uint16, mcastGroupAddresses []string) {
	igmpRule := &mcastIGMPRule{
		ruleID:       ruleID,
		priority:     priority,
		groupAddress: mcastGroupAddresses,
		event:        ruleUpdate,
	}
	c.queue.Add(igmpRule)
}

func (c *multicastController) deleteGroupAddressForTableIDs(ruleID string, groupAddresses []string) {
	igmpRule := &mcastIGMPRule{
		ruleID:       ruleID,
		groupAddress: groupAddresses,
		event:        ruleDelete,
	}
	c.queue.Add(igmpRule)
}

func (c *multicastController) validate(iface *interfacestore.InterfaceConfig,
	groupAddress net.IP, direction crdv1beta.Direction) (*v1alpha1.RuleAction, apitypes.UID, *crdv1beta.NetworkPolicyType, string, error) {

	var ruleTypePtr *crdv1beta.NetworkPolicyType
	action, uuid, ruleName := v1alpha1.RuleActionAllow, apitypes.UID(""), ""
	if iface == nil {
		// check the if iface exists
		klog.ErrorS(fmt.Errorf("iface should not be empty"), "")
		return nil, "", nil, "", fmt.Errorf("iface should not be empty")
	}
	ns, podname := iface.PodNamespace, iface.PodName
	obj, exists, _ := c.mcastItemRuleCache.GetByKey(groupAddress.String())
	if !exists {
		klog.V(2).InfoS("Rule for group does not exist", "group", groupAddress.String())
		action = v1alpha1.RuleActionAllow
		return &action, "", nil, "", nil
	}
	item := obj.(*mcastItem)
	var matchedRule *CompletedRule
	member := &crdv1beta.GroupMember{
		Pod: &crdv1beta.PodReference{
			Name:      podname,
			Namespace: ns,
		},
	}
	for ruleID := range item.ruleIDs {
		//iterate all rules relate to this multicast group address
		r, _, _ := c.ruleCache.GetCompletedRule(ruleID)
		// find the rule with highest priority
		if direction == r.Direction && r.TargetMembers.Has(member) == true {
			if (matchedRule == nil) || *(item.ruleIDs[ruleID]) > *(item.ruleIDs[matchedRule.ID]) {
				matchedRule = r
			}
		}
	}
	if matchedRule != nil {
		ruleTypePtr = new(crdv1beta.NetworkPolicyType)
		action, uuid, *ruleTypePtr, ruleName = *matchedRule.Action, matchedRule.PolicyUID, matchedRule.SourceRef.Type, matchedRule.Name
	} else {
		action, uuid, ruleName = v1alpha1.RuleActionAllow, "", ""
	}
	klog.V(2).InfoS("Call validation:", "action", action, "uuid", uuid, "ruleName", ruleName, "ruleType", ruleTypePtr)
	return &action, uuid, ruleTypePtr, ruleName, nil
}

func (c *multicastController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *multicastController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	// We expect igmpRule to come off the workqueue.
	if item, ok := obj.(*mcastIGMPRule); !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen.
		c.queue.Forget(obj)
		klog.Errorf("Expected mcastIGMPRule in work queue but got %#v", obj)
		return true
	} else if err := c.syncIGMPRule(item); err == nil {
		// If no error occurs we Forget this item, it does not get queued again until
		// another change happens.
		c.queue.Forget(item)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(item)
		klog.ErrorS(err, "error syncing multicast rule", "item", item)
	}
	return true
}

func (c *multicastController) syncIGMPRule(igmpRule *mcastIGMPRule) error {
	c.ruleIDGroupMapMutex.Lock()
	defer c.ruleIDGroupMapMutex.Unlock()
	var item *mcastItem
	switch igmpRule.event {
	case ruleAdd:
		klog.V(2).InfoS("Add rule", "igmpRule", igmpRule)
		memberList := sets.String{}
		for _, group := range igmpRule.groupAddress {
			item = &mcastItem{
				groupAddress: ip.IPv4StrToIPNet(group),
				ruleIDs:      make(map[string]*uint16),
			}
			memberList.Insert(group)
			obj, exists, _ := c.mcastItemRuleCache.GetByKey(group)
			if exists {
				//group exists
				itemOrig := obj.(*mcastItem)
				item.groupAddress = itemOrig.groupAddress
				for ruleID, priority := range itemOrig.ruleIDs {
					item.ruleIDs[ruleID] = priority
				}
			}
			item.ruleIDs[igmpRule.ruleID] = igmpRule.priority

			c.mcastItemRuleCache.Add(item)
		}
		c.ruleIDGroupAddressMap[igmpRule.ruleID] = memberList
	case ruleUpdate:
		klog.V(2).InfoS("Update rule", "igmpRule", igmpRule)
		groupAddresses, _ := c.ruleIDGroupAddressMap[igmpRule.ruleID]
		//rule changed
		members := sets.String{}
		for _, groupAddress := range igmpRule.groupAddress {
			members.Insert(groupAddress)
			item = &mcastItem{
				groupAddress: ip.IPv4StrToIPNet(groupAddress),
				ruleIDs:      make(map[string]*uint16),
			}
			if groupAddresses.Has(groupAddress) {
				//just update
				obj, exists, _ := c.mcastItemRuleCache.GetByKey(groupAddress)
				if exists {
					itemOrig := obj.(*mcastItem)
					item.groupAddress = itemOrig.groupAddress
					for ruleID, priority := range itemOrig.ruleIDs {
						item.ruleIDs[ruleID] = priority
					}
				}
			}
			item.ruleIDs[igmpRule.ruleID] = igmpRule.priority
			c.mcastItemRuleCache.Add(item)
		}
		for groupAddress := range groupAddresses {
			if !members.Has(groupAddress) {
				//remove
				obj, exists, _ := c.mcastItemRuleCache.GetByKey(groupAddress)
				if exists {
					item = &mcastItem{
						groupAddress: ip.IPv4StrToIPNet(groupAddress),
						ruleIDs:      make(map[string]*uint16),
					}
					itemOrig := obj.(*mcastItem)
					for ruleID, priority := range itemOrig.ruleIDs {
						if ruleID != igmpRule.ruleID {
							item.ruleIDs[ruleID] = priority
						}
					}
					if len(item.ruleIDs) == 0 {
						c.mcastItemRuleCache.Delete(itemOrig)
					} else {
						c.mcastItemRuleCache.Add(item)
					}
				}
			}
		}
		c.ruleIDGroupAddressMap[igmpRule.ruleID] = members
	case ruleDelete:
		//remove from cache
		klog.V(2).InfoS("Delete rule", "igmpRule", igmpRule)
		memberList := c.ruleIDGroupAddressMap[igmpRule.ruleID]
		for member := range memberList {
			obj, exists, _ := c.mcastItemRuleCache.GetByKey(member)
			item = &mcastItem{
				groupAddress: ip.IPv4StrToIPNet(member),
				ruleIDs:      make(map[string]*uint16),
			}
			if exists {
				itemOrig := obj.(*mcastItem)
				for ruleID := range itemOrig.ruleIDs {
					if ruleID != igmpRule.ruleID {
						item.ruleIDs[ruleID] = itemOrig.ruleIDs[ruleID]
					}
				}
				if len(item.ruleIDs) == 0 {
					c.mcastItemRuleCache.Delete(itemOrig)
				} else {
					c.mcastItemRuleCache.Add(item)
				}
			}
		}
		delete(c.ruleIDGroupAddressMap, igmpRule.ruleID)
	}
	return nil
}

func newMulticastNetworkPolicyController(ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore,
	ruleCache *ruleCache) (*multicastController, error) {
	mcastItemRuleCache := cache.NewIndexer(groupAddressKey, cache.Indexers{
		groupAddressIndex: groupAddressRuleIndexFunc,
	})
	mcastController := &multicastController{
		ofClient:              ofClient,
		ifaceStore:            ifaceStore,
		ruleCache:             ruleCache,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "igmpRule"),
		mcastItemRuleCache:    mcastItemRuleCache,
		ruleIDGroupAddressMap: make(map[string]sets.String),
	}
	return mcastController, nil
}

func (c *multicastController) Validate(obj interface{}, groupAddress net.IP) (interface{}, error) {
	iface := obj.(*interfacestore.InterfaceConfig)

	action, uuid, npType, name, err := c.validate(iface, groupAddress, crdv1beta.DirectionOut)
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
