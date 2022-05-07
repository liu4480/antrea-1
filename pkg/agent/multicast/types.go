package multicast

import (
	"net"

	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

type Validate interface {
	Validation(iface *interfacestore.InterfaceConfig, groupAddress net.IP) (*v1alpha1.RuleAction, types.UID, string, error)
}