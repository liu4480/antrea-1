package networkpolicy

import (
	"antrea.io/antrea/pkg/util/channel"
	"fmt"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"github.com/stretchr/testify/require"
)

func newMockMcastController(t *testing.T, controller *gomock.Controller) (*multicastController, *openflowtest.MockClient) {
	mockOFClient := openflowtest.NewMockClient(controller)
	mockIface := interfacestore.NewInterfaceStore()
	allocator := openflow.NewGroupAllocator(false)
	podUpdateChannel := channel.NewSubscribableChannel("PodUpdate", 100)
	groupID := allocator.Allocate()
	m, err := NewMulticastNetworkPolicyController(
		mockOFClient,
		mockIface,
		podUpdateChannel,
		groupID)
	fmt.Println(123)
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
				"224.0.0.1": mcastItem{
					groupAddress: net.IPNet{
						IP: net.ParseIP("224.0.0.1"),
						Mask: net.CIDRMask(32,32),
					},
					ruleIDs: map[string]*uint16{
						"queryRule01": &priority,
					},
				},
			},
			map[string]sets.String {
				"queryRule01": sets.NewString("224.0.0.1"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			m, _ := newMockMcastController(t, controller)
			go func() {
				event:= <-m.eventCh
				t.Logf("got event: %v", event.eType)
			}()
			if tt.mcastItemRuleIDMap != nil {
				m.mcastItemRuleIDMap = tt.mcastItemRuleIDMap
			}
			if tt.ruleIDGroupAddressMap != nil {
				m.ruleIDGroupAddressMap = tt.ruleIDGroupAddressMap
			}

			m.addGroupAddressForTableIDs(tt.ruleID, &priority, []string{"224.0.0.1"})
			assert.Equal(t, tt.expectedMcastItemRuleIDMap, m.mcastItemRuleIDMap)
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
			"removeQueryGroup",
			map[string]mcastItem {
				"224.0.0.1": mcastItem{
					groupAddress: net.IPNet{
						IP: net.ParseIP("224.0.0.1"),
						Mask: net.CIDRMask(32,32),
					},
					ruleIDs: map[string]*uint16{
						"queryRule01": &priority,
					},
				},
				"225.1.2.3": mcastItem{
					groupAddress: net.IPNet{
						IP: net.ParseIP("225.1.2.3"),
						Mask: net.CIDRMask(32,32),
					},
					ruleIDs: map[string]*uint16{
						"queryRule01": &priority,
					},
				},
			},
			nil,
			"queryRule01",
			map[string]mcastItem{
				"225.1.2.3": mcastItem{
					groupAddress: net.IPNet{
						IP: net.ParseIP("225.1.2.3"),
						Mask: net.CIDRMask(32,32),
					},
					ruleIDs: map[string]*uint16{
						"queryRule01": &priority,
					},
				},
			},
			map[string]sets.String {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			defer controller.Finish()
			m, _ := newMockMcastController(t, controller)
			go func() {
				event:= <-m.eventCh
				t.Logf("got event: %v", event.eType)
			}()
			if tt.mcastItemRuleIDMap != nil {
				m.mcastItemRuleIDMap = tt.mcastItemRuleIDMap
			}
			if tt.ruleIDGroupAddressMap != nil {
				m.ruleIDGroupAddressMap = tt.ruleIDGroupAddressMap
			}
			m.deleteGroupAddressForTableIDs(tt.ruleID, []string{"224.0.0.1"})
			assert.Equal(t, tt.expectedMcastItemRuleIDMap, m.mcastItemRuleIDMap)
			assert.Equal(t, tt.expectedRuleIDGroupAddressMap, m.ruleIDGroupAddressMap)
		})
	}
}

func TestValidation(t *testing.T) {

}

func TestSyncQueryGroup(t *testing.T) {

}
