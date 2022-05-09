package multicast

import (
	"net"

	"antrea.io/antrea/pkg/agent/interfacestore"
)

type Validate interface {
	Validation(iface *interfacestore.InterfaceConfig, groupAddress net.IP) (interface{}, error)
}
