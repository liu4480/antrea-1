package types

import (
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	apitypes "k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

type MulticastNPValidation struct {
	RuleAction *v1alpha1.RuleAction
	Uuid       apitypes.UID
	NPType     *v1beta2.NetworkPolicyType
	Name       string
}
