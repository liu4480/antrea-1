package multicast

import (
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/ovs/openflow"
	"k8s.io/apimachinery/pkg/types"
	"net"
)

type Validator interface {
	Initialize(bucketID openflow.GroupIDType) bool
	Validation(iface *interfacestore.InterfaceConfig, groupAddress net.IP) (*v1alpha1.RuleAction, types.UID, string, error)
}