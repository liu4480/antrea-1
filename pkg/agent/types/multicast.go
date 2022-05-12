package types

import (
	"fmt"
	"net"
	"sync"

	apitypes "k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	McastNPValidator = "McastNPValidator"
)

type McastNPValidationItem struct {
	RuleAction *v1alpha1.RuleAction
	Uuid       apitypes.UID
	NPType     *v1beta2.NetworkPolicyType
	Name       string
}

var (
	McastAllHosts = net.ParseIP("224.0.0.1").To4()
)

type ValidateHandler interface {
	Validation(iface interface{}, groupAddress net.IP) (interface{}, error)
}

type MulticastValidate interface {
	RegisterPacketInHandler(validateHandlerName string, validateHandler interface{})
	Validation(iface interface{}, groupAddress net.IP, validateName string) (interface{}, error)
}

type validate struct {
	HandlerMutex sync.RWMutex
	Handlers     map[string]interface{}
}

func (v *validate) Validation(iface interface{}, groupAddress net.IP, validateName string) (interface{}, error) {
	v.HandlerMutex.Lock()
	defer v.HandlerMutex.Unlock()
	handlerPtr, ok := v.Handlers[validateName]
	if !ok {
		return nil, fmt.Errorf("no validate handler for %s", validateName)
	}
	if handler, ok := handlerPtr.(ValidateHandler); ok {
		return handler.Validation(iface, groupAddress)
	}
	return nil, fmt.Errorf("invalid handler for %s", validateName)
}

func (v *validate) RegisterPacketInHandler(validateHandlerName string, validateHandler interface{}) {
	v.HandlerMutex.Lock()
	defer v.HandlerMutex.Unlock()
	if _, ok := v.Handlers[validateHandlerName]; !ok {
		v.Handlers[validateHandlerName] = validateHandler
	}
}

func NewValidator() (MulticastValidate, error) {
	return &validate{
		Handlers: make(map[string]interface{}),
	}, nil
}
