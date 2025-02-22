//go:build !windows
// +build !windows

// package openflow is needed by antctl which is compiled for macOS too.

// Copyright 2021 Antrea Authors
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

package openflow

import (
	"net"

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

func (c *client) InstallBridgeUplinkFlows() error {
	if !c.connectUplinkToBridge {
		return nil
	}
	// TODO(gran): support IPv6
	if c.nodeConfig.PodIPv4CIDR != nil {
		flows := c.hostBridgeUplinkFlows(*c.nodeConfig.PodIPv4CIDR, cookie.Default)
		if err := c.ofEntryOperations.AddAll(flows); err != nil {
			return err
		}
		c.hostNetworkingFlows = flows
	}
	return nil
}

func (c *client) InstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error {
	return nil
}

func (c *client) UninstallLoadBalancerServiceFromOutsideFlows(svcIP net.IP, svcPort uint16, protocol binding.Protocol) error {
	return nil
}
