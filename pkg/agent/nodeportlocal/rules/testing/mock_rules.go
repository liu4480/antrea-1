// Copyright 2021 Antrea Authors
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
//

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/rules (interfaces: PodPortRules)

// Package testing is a generated GoMock package.
package testing

import (
	gomock "github.com/golang/mock/gomock"
	rules "github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/rules"
	reflect "reflect"
)

// MockPodPortRules is a mock of PodPortRules interface
type MockPodPortRules struct {
	ctrl     *gomock.Controller
	recorder *MockPodPortRulesMockRecorder
}

// MockPodPortRulesMockRecorder is the mock recorder for MockPodPortRules
type MockPodPortRulesMockRecorder struct {
	mock *MockPodPortRules
}

// NewMockPodPortRules creates a new mock instance
func NewMockPodPortRules(ctrl *gomock.Controller) *MockPodPortRules {
	mock := &MockPodPortRules{ctrl: ctrl}
	mock.recorder = &MockPodPortRulesMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockPodPortRules) EXPECT() *MockPodPortRulesMockRecorder {
	return m.recorder
}

// AddAllRules mocks base method
func (m *MockPodPortRules) AddAllRules(arg0 []rules.PodNodePort) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddAllRules", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddAllRules indicates an expected call of AddAllRules
func (mr *MockPodPortRulesMockRecorder) AddAllRules(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddAllRules", reflect.TypeOf((*MockPodPortRules)(nil).AddAllRules), arg0)
}

// AddRule mocks base method
func (m *MockPodPortRules) AddRule(arg0 int, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddRule", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddRule indicates an expected call of AddRule
func (mr *MockPodPortRulesMockRecorder) AddRule(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddRule", reflect.TypeOf((*MockPodPortRules)(nil).AddRule), arg0, arg1)
}

// DeleteAllRules mocks base method
func (m *MockPodPortRules) DeleteAllRules() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAllRules")
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAllRules indicates an expected call of DeleteAllRules
func (mr *MockPodPortRulesMockRecorder) DeleteAllRules() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAllRules", reflect.TypeOf((*MockPodPortRules)(nil).DeleteAllRules))
}

// DeleteRule mocks base method
func (m *MockPodPortRules) DeleteRule(arg0 int, arg1 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteRule", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteRule indicates an expected call of DeleteRule
func (mr *MockPodPortRulesMockRecorder) DeleteRule(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteRule", reflect.TypeOf((*MockPodPortRules)(nil).DeleteRule), arg0, arg1)
}

// Init mocks base method
func (m *MockPodPortRules) Init() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Init")
	ret0, _ := ret[0].(error)
	return ret0
}

// Init indicates an expected call of Init
func (mr *MockPodPortRulesMockRecorder) Init() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Init", reflect.TypeOf((*MockPodPortRules)(nil).Init))
}
