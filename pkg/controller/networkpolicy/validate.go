// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networkpolicy

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/env"
)

// validator interface introduces the set of functions that must be implemented
// by any resource validator.
type validator interface {
	// createValidate is the interface which must be satisfied for resource
	// CREATE events.
	createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool)
	// updateValidate is the interface which must be satisfied for resource
	// UPDATE events.
	updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool)
	// deleteValidate is the interface which must be satisfied for resource
	// DELETE events.
	deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool)
}

// resourceValidator maintains a reference of the NetworkPolicyController and
// provides a base struct for validating objects which implement the validator
// interface.
type resourceValidator struct {
	networkPolicyController *NetworkPolicyController
}

// antreaPolicyValidator implements the validator interface for Antrea-native
// policies.
type antreaPolicyValidator resourceValidator

// tierValidator implements the validator interface for Tier resources.
type tierValidator resourceValidator

// groupValidator implements the validator interface for the ClusterGroup resource.
type groupValidator resourceValidator

var (
	// reservedTierPriorities stores the reserved priority range from 251, 252, 254 and 255.
	// The priority 250 is reserved for default Tier but not part of this set in order to be
	// able to create the Tier by Antrea. Same for priority 253 which is reserved for the
	// baseline tier.
	reservedTierPriorities = sets.NewInt32(int32(251), int32(252), int32(254), int32(255))
	// reservedTierNames stores the set of Tier names which cannot be deleted
	// since they are created by Antrea.
	reservedTierNames = sets.NewString("baseline", "application", "platform", "networkops", "securityops", "emergency")
	// allowedFQDNChars validates that the matchPattern field contains only valid DNS characters
	// and the wildcard '*' character.
	allowedFQDNChars = regexp.MustCompile("^[-0-9a-zA-Z.*]+$")
)

// RegisterAntreaPolicyValidator registers an Antrea-native policy validator
// to the resource registry. A new validator must be registered by calling
// this function before the Run phase of the APIServer.
func (v *NetworkPolicyValidator) RegisterAntreaPolicyValidator(a validator) {
	v.antreaPolicyValidators = append(v.antreaPolicyValidators, a)
}

// RegisterTierValidator registers a Tier validator to the resource registry.
// A new validator must be registered by calling this function before the Run
// phase of the APIServer.
func (v *NetworkPolicyValidator) RegisterTierValidator(t validator) {
	v.tierValidators = append(v.tierValidators, t)
}

// RegisterGroupValidator registers a Group validator to the resource registry.
// A new validator must be registered by calling this function before the Run
// phase of the APIServer.
func (v *NetworkPolicyValidator) RegisterGroupValidator(g validator) {
	v.groupValidators = append(v.groupValidators, g)
}

// NetworkPolicyValidator maintains list of validator objects which validate
// the Antrea-native policy related resources.
type NetworkPolicyValidator struct {
	// antreaPolicyValidators maintains a list of validator objects which
	// implement the validator interface for Antrea-native policies.
	antreaPolicyValidators []validator
	// tierValidators maintains a list of validator objects which
	// implement the validator interface for Tier resources.
	tierValidators []validator
	// groupValidators maintains a list of validator objects which
	// implement the validator interface for ClusterGroup resources.
	groupValidators []validator
}

// NewNetworkPolicyValidator returns a new *NetworkPolicyValidator.
func NewNetworkPolicyValidator(networkPolicyController *NetworkPolicyController) *NetworkPolicyValidator {
	// initialize the validator registry with the default validators that need to
	// be called.
	vr := NetworkPolicyValidator{}
	// apv is an instance of antreaPolicyValidator to validate Antrea-native
	// policy events.
	apv := antreaPolicyValidator{
		networkPolicyController: networkPolicyController,
	}
	// tv is an instance of tierValidator to validate Tier resource events.
	tv := tierValidator{
		networkPolicyController: networkPolicyController,
	}
	// gv is an instance of groupValidator to validate ClusterGroup
	// resource events.
	gv := groupValidator{
		networkPolicyController: networkPolicyController,
	}
	vr.RegisterAntreaPolicyValidator(&apv)
	vr.RegisterTierValidator(&tv)
	vr.RegisterGroupValidator(&gv)
	return &vr
}

// Validate function validates a ClusterGroup, Tier or Antrea Policy object
func (v *NetworkPolicyValidator) Validate(ar *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := false
	op := ar.Request.Operation
	ui := ar.Request.UserInfo
	curRaw := ar.Request.Object.Raw
	oldRaw := ar.Request.OldObject.Raw
	switch ar.Request.Kind.Kind {
	case "Tier":
		klog.V(2).Info("Validating Tier CRD")
		var curTier, oldTier crdv1alpha1.Tier
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curTier); err != nil {
				klog.Errorf("Error de-serializing current Tier")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldTier); err != nil {
				klog.Errorf("Error de-serializing old Tier")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateTier(&curTier, &oldTier, op, ui)
	case "ClusterGroup":
		klog.V(2).Info("Validating ClusterGroup CRD")
		var curCG, oldCG crdv1alpha2.ClusterGroup
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curCG); err != nil {
				klog.Errorf("Error de-serializing current ClusterGroup")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldCG); err != nil {
				klog.Errorf("Error de-serializing old ClusterGroup")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAntreaGroup(&curCG, &oldCG, op, ui)
	case "ClusterNetworkPolicy":
		klog.V(2).Info("Validating Antrea ClusterNetworkPolicy CRD")
		var curCNP, oldCNP crdv1alpha1.ClusterNetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curCNP); err != nil {
				klog.Errorf("Error de-serializing current Antrea ClusterNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldCNP); err != nil {
				klog.Errorf("Error de-serializing old Antrea ClusterNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAntreaPolicy(&curCNP, &oldCNP, op, ui)
	case "NetworkPolicy":
		klog.V(2).Info("Validating Antrea NetworkPolicy CRD")
		var curANP, oldANP crdv1alpha1.NetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curANP); err != nil {
				klog.Errorf("Error de-serializing current Antrea NetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldANP); err != nil {
				klog.Errorf("Error de-serializing old Antrea NetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAntreaPolicy(&curANP, &oldANP, op, ui)
	}
	if msg != "" {
		result = &metav1.Status{
			Message: msg,
		}
	}
	return &admv1.AdmissionResponse{
		Allowed: allowed,
		Result:  result,
	}
}

// validateAntreaPolicy validates the admission of a Antrea NetworkPolicy CRDs
func (v *NetworkPolicyValidator) validateAntreaPolicy(curObj, oldObj interface{}, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		for _, val := range v.antreaPolicyValidators {
			reason, allowed = val.createValidate(curObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Update:
		for _, val := range v.antreaPolicyValidators {
			reason, allowed = val.updateValidate(curObj, oldObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Delete:
		// Delete of Antrea Policies have no validation. This will be an
		// empty for loop.
		for _, val := range v.antreaPolicyValidators {
			reason, allowed = val.deleteValidate(oldObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return reason, allowed
}

// validatePort validates if ports is valid
func (v *antreaPolicyValidator) validatePort(ingress, egress []crdv1alpha1.Rule) error {
	isValid := func(rules []crdv1alpha1.Rule) error {
		for _, rule := range rules {
			for _, port := range rule.Ports {
				if port.EndPort == nil {
					continue
				}
				if port.Port == nil {
					return fmt.Errorf("if `endPort` is specified `port` must be specified")
				}
				if port.Port.Type == intstr.String {
					return fmt.Errorf("if `port` is a string `endPort` cannot be specified")
				}
				if *port.EndPort < port.Port.IntVal {
					return fmt.Errorf("`endPort` should be greater than or equal to `port`")
				}
			}
		}
		return nil
	}
	if err := isValid(ingress); err != nil {
		return err
	}
	if err := isValid(egress); err != nil {
		return err
	}
	return nil
}

// validateAntreaGroup validates the admission of a ClusterGroup resource
func (v *NetworkPolicyValidator) validateAntreaGroup(curCG, oldCG *crdv1alpha2.ClusterGroup, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for ClusterGroup")
		for _, val := range v.groupValidators {
			reason, allowed = val.createValidate(curCG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for ClusterGroup")
		for _, val := range v.groupValidators {
			reason, allowed = val.updateValidate(curCG, oldCG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for ClusterGroup")
		for _, val := range v.groupValidators {
			reason, allowed = val.deleteValidate(oldCG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return reason, allowed
}

// validateTier validates the admission of a Tier resource
func (v *NetworkPolicyValidator) validateTier(curTier, oldTier *crdv1alpha1.Tier, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for Tier")
		for _, val := range v.tierValidators {
			reason, allowed = val.createValidate(curTier, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Update:
		// Tier priority updates are not allowed
		klog.V(2).Info("Validating UPDATE request for Tier")
		for _, val := range v.tierValidators {
			reason, allowed = val.updateValidate(curTier, oldTier, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for Tier")
		for _, val := range v.tierValidators {
			reason, allowed = val.deleteValidate(oldTier, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return reason, allowed
}

func (v *antreaPolicyValidator) tierExists(name string) bool {
	_, err := v.networkPolicyController.tierLister.Get(name)
	return err == nil
}

// GetAdmissionResponseForErr returns an object of type AdmissionResponse with
// the submitted error message.
func GetAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	if err == nil {
		return nil
	}
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

// createValidate validates the CREATE events of Antrea-native policies,
func (v *antreaPolicyValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	var tier string
	var ingress, egress []crdv1alpha1.Rule
	var specAppliedTo []crdv1alpha1.NetworkPolicyPeer
	switch curObj.(type) {
	case *crdv1alpha1.ClusterNetworkPolicy:
		curCNP := curObj.(*crdv1alpha1.ClusterNetworkPolicy)
		tier = curCNP.Spec.Tier
		ingress = curCNP.Spec.Ingress
		egress = curCNP.Spec.Egress
		specAppliedTo = curCNP.Spec.AppliedTo
	case *crdv1alpha1.NetworkPolicy:
		curANP := curObj.(*crdv1alpha1.NetworkPolicy)
		tier = curANP.Spec.Tier
		ingress = curANP.Spec.Ingress
		egress = curANP.Spec.Egress
		specAppliedTo = curANP.Spec.AppliedTo
	}
	reason, allowed := v.validateTierForPolicy(tier)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateTierForPassAction(tier, ingress, egress)
	if !allowed {
		return reason, allowed
	}
	if ruleNameUnique := v.validateRuleName(ingress, egress); !ruleNameUnique {
		return "rules names must be unique within the policy", false
	}
	reason, allowed = v.validateAppliedTo(ingress, egress, specAppliedTo)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validatePeers(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateFQDNSelectors(egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateEgressMulticastAddress(egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateMulticastIGMP(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	if err := v.validatePort(ingress, egress); err != nil {
		return err.Error(), false
	}
	return "", true
}

// validateRuleName validates if the name of each rule is unique within a policy
func (v *antreaPolicyValidator) validateRuleName(ingress, egress []crdv1alpha1.Rule) bool {
	uniqueRuleName := sets.NewString()
	isUnique := func(rules []crdv1alpha1.Rule) bool {
		for _, rule := range rules {
			if uniqueRuleName.Has(rule.Name) {
				return false
			}
			uniqueRuleName.Insert(rule.Name)
		}
		return true
	}
	return isUnique(ingress) && isUnique(egress)
}

func (v *antreaPolicyValidator) validateAppliedTo(ingress, egress []crdv1alpha1.Rule, specAppliedTo []crdv1alpha1.NetworkPolicyPeer) (string, bool) {
	appliedToInSpec := len(specAppliedTo) != 0
	countAppliedToInRules := func(rules []crdv1alpha1.Rule) int {
		num := 0
		for _, rule := range rules {
			if len(rule.AppliedTo) != 0 {
				num++
			}
		}
		return num
	}
	numAppliedToInRules := countAppliedToInRules(ingress) + countAppliedToInRules(egress)
	// Ensure that AppliedTo is not set in both spec and rules.
	if appliedToInSpec && (numAppliedToInRules > 0) {
		return "appliedTo should not be set in both spec and rules", false
	}
	if !appliedToInSpec && (numAppliedToInRules == 0) {
		return "appliedTo needs to be set in either spec or rules", false
	}
	// Ensure that all rules have AppliedTo set.
	if numAppliedToInRules > 0 && (numAppliedToInRules != len(ingress)+len(egress)) {
		return "appliedTo field should either be set in all rules or in none of them", false
	}

	checkAppliedTo := func(appliedTo []crdv1alpha1.NetworkPolicyPeer) (string, bool) {
		for _, eachAppliedTo := range appliedTo {
			appliedToFieldsNum := numFieldsSetInPeer(eachAppliedTo)
			if eachAppliedTo.Group != "" && appliedToFieldsNum > 1 {
				return "group cannot be set with other peers in appliedTo", false
			}
			if eachAppliedTo.ServiceAccount != nil && appliedToFieldsNum > 1 {
				return "serviceAccount cannot be set with other peers in appliedTo", false
			}
			if reason, allowed := checkSelectorsLabels(eachAppliedTo.PodSelector, eachAppliedTo.NamespaceSelector, eachAppliedTo.ExternalEntitySelector); !allowed {
				return reason, allowed
			}
		}
		return "", true
	}

	reason, allowed := checkAppliedTo(specAppliedTo)
	if !allowed {
		return reason, allowed
	}

	for _, eachIngress := range ingress {
		reason, allowed = checkAppliedTo(eachIngress.AppliedTo)
		if !allowed {
			return reason, allowed
		}
	}
	for _, eachEgress := range egress {
		reason, allowed = checkAppliedTo(eachEgress.AppliedTo)
		if !allowed {
			return reason, allowed
		}
	}
	return "", true
}

// validatePeers ensures that the NetworkPolicyPeer object set in rules are valid, i.e.
// currently it ensures that a Group cannot be set with other stand-alone selectors or IPBlock.
func (v *antreaPolicyValidator) validatePeers(ingress, egress []crdv1alpha1.Rule) (string, bool) {
	checkPeers := func(peers []crdv1alpha1.NetworkPolicyPeer) (string, bool) {
		for _, peer := range peers {
			if peer.NamespaceSelector != nil && peer.Namespaces != nil {
				return "namespaces and namespaceSelector cannot be set at the same time for a single NetworkPolicyPeer", false
			}
			peerFieldsNum := numFieldsSetInPeer(peer)
			if peer.Group != "" && peerFieldsNum > 1 {
				return "group cannot be set with other peers in rules", false
			}
			if peer.ServiceAccount != nil && peerFieldsNum > 1 {
				return "serviceAccount cannot be set with other peers in rules", false
			}
			if peer.NodeSelector != nil && peerFieldsNum > 1 {
				return "nodeSelector cannot be set with other peers in rules", false
			}
			if reason, allowed := checkSelectorsLabels(peer.PodSelector, peer.NamespaceSelector, peer.ExternalEntitySelector, peer.NodeSelector); !allowed {
				return reason, allowed
			}
		}
		return "", true
	}
	for _, rule := range ingress {
		msg, isValid := checkPeers(rule.From)
		if !isValid {
			return msg, false
		}
	}
	for _, rule := range egress {
		if rule.ToServices != nil {
			if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
				return fmt.Sprintf("`toServices` can only be used when AntreaProxy is enabled"), false
			}
			if (rule.To != nil && len(rule.To) > 0) || rule.Ports != nil || rule.Protocols != nil {
				return fmt.Sprintf("`toServices` can't be used with `to`, `ports` or `protocols`"), false
			}
		}
		msg, isValid := checkPeers(rule.To)
		if !isValid {
			return msg, false
		}
	}
	return "", true
}

// numFieldsSetInPeer returns the number of fields in use of a peer.
func numFieldsSetInPeer(peer crdv1alpha1.NetworkPolicyPeer) int {
	num := 0
	v := reflect.ValueOf(peer)
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsZero() {
			num++
		}
	}
	return num
}

// checkSelectorsLabels validates labels used in all selectors passed in.
func checkSelectorsLabels(selectors ...*metav1.LabelSelector) (string, bool) {
	validateLabels := func(labels map[string]string) (string, bool) {
		for k, v := range labels {
			err := validation.IsQualifiedName(k)
			if err != nil {
				return fmt.Sprintf("Invalid label key: %s: %s", k, strings.Join(err, "; ")), false
			}
			err = validation.IsValidLabelValue(v)
			if err != nil {
				return fmt.Sprintf("Invalid label value: %s: %s", v, strings.Join(err, "; ")), false
			}
		}
		return "", true
	}
	for _, selector := range selectors {
		if selector != nil {
			if reason, allowed := validateLabels(selector.MatchLabels); !allowed {
				return reason, allowed
			}
		}
	}
	return "", true
}

// validateTierForPolicy validates whether a referenced Tier exists.
func (v *antreaPolicyValidator) validateTierForPolicy(tier string) (string, bool) {
	// "tier" must exist before referencing
	if tier == "" || staticTierSet.Has(tier) {
		// Empty Tier name corresponds to default Tier.
		return "", true
	}
	if ok := v.tierExists(tier); !ok {
		reason := fmt.Sprintf("tier %s does not exist", tier)
		return reason, false
	}
	return "", true
}

// validateTierForPassAction validates that rules with pass action are not created in the Baseline Tier.
func (v *antreaPolicyValidator) validateTierForPassAction(tier string, ingress, egress []crdv1alpha1.Rule) (string, bool) {
	if strings.ToLower(tier) != baselineTierName {
		return "", true
	}
	for _, rule := range ingress {
		if *rule.Action == crdv1alpha1.RuleActionPass {
			return fmt.Sprintf("`Pass` action should not be set for Baseline Tier policy rules"), false
		}
	}
	for _, rule := range egress {
		if *rule.Action == crdv1alpha1.RuleActionPass {
			return fmt.Sprintf("`Pass` action should not be set for Baseline Tier policy rules"), false
		}
	}
	return "", true
}

func (v *antreaPolicyValidator) validateEgressMulticastAddress(egressRule []crdv1alpha1.Rule) (string, bool) {
	for _, r := range egressRule {
		multicast := false
		unicast := false
		otherSelectors := false
		for _, to := range r.To {
			toIPAddr, _, err := net.ParseCIDR(to.IPBlock.CIDR)
			if err != nil {
				return fmt.Sprintf("invalid multicast ip address (to.IPBlock.CIDR): %v", err.Error()), false
			}
			if toIPAddr.IsMulticast() {
				multicast = true
			} else{
				unicast = true
			}
			if to.PodSelector != nil || to.NamespaceSelector != nil || to.Namespaces != nil ||
				to.ExternalEntitySelector != nil || to.ServiceAccount != nil || to.NodeSelector != nil {
				otherSelectors = true
			}
			if multicast && unicast {
				return fmt.Sprintf("can not set multicast ip address and unicast ip address at the same time"), false
			}
			if multicast && otherSelectors {
				return fmt.Sprintf("can not set multicast ip address and selectors at the same time"), false
			}
		}
	}
	return "", true
}

func igmpValidation(protocol crdv1alpha1.NetworkPolicyProtocol) (string, bool) {
	if protocol.IGMP != nil {
		if protocol.ICMP != nil {
			return fmt.Sprintf("icmp can not set with igmp in a single rule"), false
		}
		if protocol.IGMP.IGMPType != nil && (*protocol.IGMP.IGMPType != crdv1alpha1.IGMPQuery) && (*protocol.IGMP.IGMPType != crdv1alpha1.IGMPReport) {
			return fmt.Sprintf("invalid IGMP type: %s, expected are: %s or %s",
				*protocol.IGMP.IGMPType, crdv1alpha1.IGMPQuery, crdv1alpha1.IGMPReport), false
		}
		groupIP, _, err := net.ParseCIDR(protocol.IGMP.GroupAddress.CIDR)
		if err != nil {
			return fmt.Sprintf("invalid ipaddress %s error %s",
				protocol.IGMP.GroupAddress.CIDR, err.Error()), false
		}
		if groupIP.IsMulticast() == false {
			return fmt.Sprintf("ipaddress %+v(cidr %s) is not multicast",
					groupIP, protocol.IGMP.GroupAddress.CIDR), false
		}

	}
	return "", true
}

func (v *antreaPolicyValidator) validateMulticastIGMP(ingressRules, egressRules []crdv1alpha1.Rule) (string, bool) {
	for _, r := range ingressRules {
		for _, protocol := range r.Protocols {
			reason, allowed := igmpValidation(protocol)
			if !allowed {
				return reason, allowed
			}
		}
	}
	for _, r := range egressRules {
		for _, protocol := range r.Protocols {
			reason, allowed := igmpValidation(protocol)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return "", true
}
// validateFQDNSelectors validates the toFQDN field set in Antrea-native policy egress rules are valid.
func (v *antreaPolicyValidator) validateFQDNSelectors(egressRules []crdv1alpha1.Rule) (string, bool) {
	for _, r := range egressRules {
		for _, peer := range r.To {
			if len(peer.FQDN) > 0 && !allowedFQDNChars.MatchString(peer.FQDN) {
				return fmt.Sprintf("invalid characters in egress rule fqdn field: %s", peer.FQDN), false
			}
		}
	}
	return "", true
}

// updateValidate validates the UPDATE events of Antrea-native policies.
func (v *antreaPolicyValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	var tier string
	var ingress, egress []crdv1alpha1.Rule
	var specAppliedTo []crdv1alpha1.NetworkPolicyPeer
	switch curObj.(type) {
	case *crdv1alpha1.ClusterNetworkPolicy:
		curCNP := curObj.(*crdv1alpha1.ClusterNetworkPolicy)
		tier = curCNP.Spec.Tier
		ingress = curCNP.Spec.Ingress
		egress = curCNP.Spec.Egress
		specAppliedTo = curCNP.Spec.AppliedTo
	case *crdv1alpha1.NetworkPolicy:
		curANP := curObj.(*crdv1alpha1.NetworkPolicy)
		tier = curANP.Spec.Tier
		ingress = curANP.Spec.Ingress
		egress = curANP.Spec.Egress
		specAppliedTo = curANP.Spec.AppliedTo
	}
	reason, allowed := v.validateAppliedTo(ingress, egress, specAppliedTo)
	if !allowed {
		return reason, allowed
	}
	if ruleNameUnique := v.validateRuleName(ingress, egress); !ruleNameUnique {
		return "rules names must be unique within the policy", false
	}
	reason, allowed = v.validatePeers(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateFQDNSelectors(egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateEgressMulticastAddress(egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateMulticastIGMP(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	if err := v.validatePort(ingress, egress); err != nil {
		return err.Error(), false
	}
	reason, allowed = v.validateTierForPassAction(tier, ingress, egress)
	if !allowed {
		return reason, allowed
	}
	return v.validateTierForPolicy(tier)
}

// deleteValidate validates the DELETE events of Antrea-native policies.
func (v *antreaPolicyValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return "", true
}

// createValidate validates the CREATE events of Tier resources.
func (t *tierValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	if len(t.networkPolicyController.tierInformer.Informer().GetIndexer().ListIndexFuncValues(PriorityIndex)) >= maxSupportedTiers {
		return fmt.Sprintf("maximum number of Tiers supported: %d", maxSupportedTiers), false
	}
	curTier := curObj.(*crdv1alpha1.Tier)
	// Tier priority must not overlap reserved tier's priority.
	if reservedTierPriorities.Has(curTier.Spec.Priority) {
		return fmt.Sprintf("tier %s priority %d is reserved", curTier.Name, curTier.Spec.Priority), false
	}
	// Tier priority must not overlap existing tier's priority
	trs, err := t.networkPolicyController.tierInformer.Informer().GetIndexer().ByIndex(PriorityIndex, strconv.FormatInt(int64(curTier.Spec.Priority), 10))
	if err != nil || len(trs) > 0 {
		return fmt.Sprintf("tier %s priority %d overlaps with existing Tier", curTier.Name, curTier.Spec.Priority), false
	}
	return "", true
}

// updateValidate validates the UPDATE events of Tier resources.
func (t *tierValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	curTier := curObj.(*crdv1alpha1.Tier)
	oldTier := oldObj.(*crdv1alpha1.Tier)
	// Retrieve antrea-controller's Namespace
	namespace := env.GetAntreaNamespace()
	// Allow exception of Tier Priority updates performed by the antrea-controller
	if serviceaccount.MatchesUsername(namespace, env.GetAntreaControllerServiceAccount(), userInfo.Username) {
		return "", true
	}
	if curTier.Spec.Priority != oldTier.Spec.Priority {
		allowed = false
		reason = "update to Tier priority is not allowed"
	}
	return reason, allowed
}

// deleteValidate validates the DELETE events of Tier resources.
func (t *tierValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	oldTier := oldObj.(*crdv1alpha1.Tier)
	if reservedTierNames.Has(oldTier.Name) {
		return fmt.Sprintf("cannot delete reserved tier %s", oldTier.Name), false
	}
	// Tier with existing ACNPs/ANPs cannot be deleted.
	cnps, err := t.networkPolicyController.cnpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
	if err != nil || len(cnps) > 0 {
		return fmt.Sprintf("tier %s is referenced by %d Antrea ClusterNetworkPolicies", oldTier.Name, len(cnps)), false
	}
	anps, err := t.networkPolicyController.anpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
	if err != nil || len(anps) > 0 {
		return fmt.Sprintf("tier %s is referenced by %d Antrea NetworkPolicies", oldTier.Name, len(anps)), false
	}
	return "", true
}

// validateAntreaGroupSpec ensures that an IPBlock is not set along with namespaceSelector and/or a
// podSelector. Similarly, ExternalEntitySelector cannot be set with PodSelector.
func validateAntreaGroupSpec(s crdv1alpha2.GroupSpec) (string, bool) {
	errMsg := "At most one of podSelector, externalEntitySelector, serviceReference, ipBlock, ipBlocks or childGroups can be set for a ClusterGroup"
	if s.PodSelector != nil && s.ExternalEntitySelector != nil {
		return errMsg, false
	}
	selector, serviceRef, ipBlock, ipBlocks, childGroups := 0, 0, 0, 0, 0
	if s.NamespaceSelector != nil || s.ExternalEntitySelector != nil || s.PodSelector != nil {
		if reason, allowed := checkSelectorsLabels(s.PodSelector, s.NamespaceSelector, s.ExternalEntitySelector); !allowed {
			return reason, allowed
		}
		selector = 1
	}
	if s.IPBlock != nil {
		ipBlock = 1
	}
	if len(s.IPBlocks) > 0 {
		ipBlocks = 1
	}
	if s.ServiceReference != nil {
		serviceRef = 1
	}
	if len(s.ChildGroups) > 0 {
		childGroups = 1
	}
	if selector+serviceRef+ipBlock+ipBlocks+childGroups > 1 {
		return errMsg, false
	}
	multicast := false
	unicast := false
	for _, ipb := range s.IPBlocks {
		ipaddr, _, err :=net.ParseCIDR(ipb.CIDR)
		if err != nil {
			continue
		}
		if ipaddr.IsMulticast() {
			multicast = true
		} else {
			unicast = true
		}
		if multicast && unicast {
			return "can not set multicast ipaddress together with unicast ip address", false
		}
	}
	return "", true
}

func (g *groupValidator) validateChildGroup(s *crdv1alpha2.ClusterGroup) (string, bool) {
	if len(s.Spec.ChildGroups) > 0 {
		parentGrps, err := g.networkPolicyController.internalGroupStore.GetByIndex(store.ChildGroupIndex, s.Name)
		if err != nil {
			return fmt.Sprintf("error retrieving parents of ClusterGroup %s: %v", s.Name, err), false
		}
		// TODO: relax this constraint when max group nesting level increases.
		if len(parentGrps) > 0 {
			return fmt.Sprintf("cannot set childGroups for ClusterGroup %s, who has %d parents", s.Name, len(parentGrps)), false
		}
		for _, groupname := range s.Spec.ChildGroups {
			cg, err := g.networkPolicyController.cgLister.Get(string(groupname))
			if err != nil {
				// the childGroup has not been created yet.
				continue
			}
			// TODO: relax this constraint when max group nesting level increases.
			if len(cg.Spec.ChildGroups) > 0 {
				return fmt.Sprintf("cannot set ClusterGroup %s as childGroup, who has %d childGroups itself", string(groupname), len(cg.Spec.ChildGroups)), false
			}
		}
	}
	return "", true
}

// createValidate validates the CREATE events of ClusterGroup resources.
func (g *groupValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	curCG := curObj.(*crdv1alpha2.ClusterGroup)
	reason, allowed := validateAntreaGroupSpec(curCG.Spec)
	if !allowed {
		return reason, allowed
	}
	return g.validateChildGroup(curCG)
}

// updateValidate validates the UPDATE events of ClusterGroup resources.
func (g *groupValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	curCG := curObj.(*crdv1alpha2.ClusterGroup)
	reason, allowed := validateAntreaGroupSpec(curCG.Spec)
	if !allowed {
		return reason, allowed
	}
	return g.validateChildGroup(curCG)
}

// deleteValidate validates the DELETE events of ClusterGroup resources.
func (g *groupValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return "", true
}
