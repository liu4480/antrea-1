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
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
)

func newMockMcastController(t *testing.T, controller *gomock.Controller) (*multicastController, *openflowtest.MockClient) {
	mockOFClient := openflowtest.NewMockClient(controller)
	mockIface := interfacestore.NewInterfaceStore()
	m, err := newMulticastNetworkPolicyController(
		mockOFClient,
		mockIface,
		nil)
	require.NoError(t, err)
	return m, mockOFClient
}

func TestAddGroupAddressForTableIDs(t *testing.T) {
	priority := uint16(5)
	tests := []struct {
		name                          string
		mcastItemRuleIDMap            map[string]mcastItem
		ruleIDGroupAddressMap         map[string]sets.String
		ruleID                        string
		expectedMcastItemRuleIDMap    map[string]mcastItem
		expectedRuleIDGroupAddressMap map[string]sets.String
	}{
		{
			"addQueryGroup",
			nil,
			nil,
			"queryRule01",
			map[string]mcastItem{
				"224.0.0.1": {
					groupAddress: net.IPNet{
						IP:   net.ParseIP("224.0.0.1"),
						Mask: net.CIDRMask(32, 32),
					},
					ruleIDs: map[string]*uint16{
						"queryRule01": &priority,
					},
				},
				"225.1.2.3": {
					groupAddress: net.IPNet{
						IP:   net.ParseIP("225.1.2.3"),
						Mask: net.CIDRMask(32, 32),
					},
					ruleIDs: map[string]*uint16{
						"queryRule01": &priority,
					},
				},
			},
			map[string]sets.String{
				"queryRule01": sets.NewString("224.0.0.1", "225.1.2.3"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			m, _ := newMockMcastController(t, controller)
			if tt.ruleIDGroupAddressMap != nil {
				m.ruleIDGroupAddressMap = tt.ruleIDGroupAddressMap
			}
			for key := range tt.expectedMcastItemRuleIDMap {
				item := tt.expectedMcastItemRuleIDMap[key]
				m.mcastItemRuleCache.Add(&item)
			}

			mcastItemRuleIDMap := make(map[string]mcastItem)
			for key := range tt.expectedMcastItemRuleIDMap {
				obj, exists, _ := m.mcastItemRuleCache.GetByKey(key)

				if exists {
					item := obj.(*mcastItem)
					mcastItemRuleIDMap[key] = *item
				}
			}

			m.ruleIDGroupAddressMap["queryRule01"] = sets.NewString("224.0.0.1", "225.1.2.3")
			assert.Equal(t, tt.expectedMcastItemRuleIDMap, mcastItemRuleIDMap)
			assert.Equal(t, tt.expectedRuleIDGroupAddressMap, m.ruleIDGroupAddressMap)
		})
	}
}

func TestDeleteGroupAddressForTableIDs(t *testing.T) {
	priority := uint16(5)
	tests := []struct {
		name                          string
		mcastItemRuleIDMap            map[string]mcastItem
		ruleIDGroupAddressMap         map[string]sets.String
		ruleID                        string
		expectedMcastItemRuleIDMap    map[string]mcastItem
		expectedRuleIDGroupAddressMap map[string]sets.String
	}{
		{
			"removeGroup",
			map[string]mcastItem{
				"224.0.0.1": {
					groupAddress: net.IPNet{
						IP:   net.ParseIP("224.0.0.1"),
						Mask: net.CIDRMask(32, 32),
					},
					ruleIDs: map[string]*uint16{
						"rule01": &priority,
					},
				},
				"225.1.2.3": {
					groupAddress: net.IPNet{
						IP:   net.ParseIP("225.1.2.3"),
						Mask: net.CIDRMask(32, 32),
					},
					ruleIDs: map[string]*uint16{
						"rule01": &priority,
					},
				},
			},
			nil,
			"rule01",
			map[string]mcastItem{},
			map[string]sets.String{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			m, _ := newMockMcastController(t, controller)
			if tt.ruleIDGroupAddressMap != nil {
				m.ruleIDGroupAddressMap = tt.ruleIDGroupAddressMap
			}
			for key := range tt.mcastItemRuleIDMap {
				item := tt.mcastItemRuleIDMap[key]
				m.mcastItemRuleCache.Add(&item)
			}

			for key := range tt.mcastItemRuleIDMap {
				obj, exists, _ := m.mcastItemRuleCache.GetByKey(key)
				if exists {
					item := obj.(*mcastItem)
					m.mcastItemRuleCache.Delete(item)
				}
			}

			mcastItemRuleIDMap := make(map[string]mcastItem)
			for _, obj := range m.mcastItemRuleCache.List() {
				item := obj.(*mcastItem)
				mcastItemRuleIDMap[item.groupAddress.IP.String()] = *item
			}
			assert.Equal(t, tt.expectedMcastItemRuleIDMap, mcastItemRuleIDMap)
			assert.Equal(t, tt.expectedRuleIDGroupAddressMap, m.ruleIDGroupAddressMap)
		})
	}
}
