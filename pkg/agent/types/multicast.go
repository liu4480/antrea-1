package types

import (
	"net"

	apitypes "k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

type MulticastNPValidation struct {
	RuleAction *v1alpha1.RuleAction
	Uuid       apitypes.UID
	NPType     *v1beta2.NetworkPolicyType
	Name       string
}

var (
	McastAllHosts = net.ParseIP("224.0.0.1").To4()
)
