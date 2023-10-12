// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

// PodToK8sLocal sends an ICMP ping from all client Pods to all nodes
// in the test context.
func PodToK8sLocal() check.Scenario {
	return &podToK8sLocal{}
}

// podToK8sLocal implements a Scenario.
type podToK8sLocal struct{}

func (s *podToK8sLocal) Name() string {
	return "pod-to-k8s-local"
}

func (s *podToK8sLocal) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	pod := ct.ControlPlaneClientPod()
	k8sSvc := ct.K8sService()
	t.NewAction(s, "curl-k8s", pod, k8sSvc, features.IPFamilyAny).Run(func(a *check.Action) {
		a.ExecInPod(ctx, ct.CurlCommand(k8sSvc, features.IPFamilyAny))
		a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
			DNSRequired: true,
			AltDstPort:  k8sSvc.Port(),
		}))

		a.ValidateMetrics(ctx, *pod, a.GetEgressMetricsRequirements())
	})
}
