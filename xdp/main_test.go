package xdp

import "testing"

func TestMakeRuleKeyRejectsSpecificListenIP(t *testing.T) {
	_, err := makeRuleKey(runtimeRule{
		ListenIP:   "203.0.113.10",
		ListenPort: 443,
		Protocol:   "tcp",
		IPVersion:  4,
	})
	if err == nil {
		t.Fatalf("makeRuleKey error=nil, want specific listen_ip error")
	}
}

func TestMakeRuleValEncodesForwardingFields(t *testing.T) {
	got, err := makeRuleVal(runtimeRule{
		Index:               7,
		UserIndex:           3,
		ResolvedTarget:      "198.51.100.8",
		RemotePort:          8443,
		SNATMode:            "snat",
		SNATSource:          "198.51.100.1",
		MSSMode:             "set",
		MSSValue:            1360,
		TrafficMode:         "two-way",
		TrafficRatio:        1.5,
		RuleLimit:           1000,
		UserLimit:           2000,
		BillingUsedBase:     10,
		UserBillingUsedBase: 20,
	})
	if err != nil {
		t.Fatalf("makeRuleVal: %v", err)
	}
	if got.RuleID != 7 || got.UserID != 3 {
		t.Fatalf("ids=%d/%d, want 7/3", got.RuleID, got.UserID)
	}
	if got.TargetPort != htons(8443) {
		t.Fatalf("target port=%d, want %d", got.TargetPort, htons(8443))
	}
	if got.SNATMode != 1 || got.MSSMode != 2 || got.MSSValue != 1360 {
		t.Fatalf("snat/mss=%d/%d/%d, want 1/2/1360", got.SNATMode, got.MSSMode, got.MSSValue)
	}
	if got.TrafficRatioScaled != 1_500_000 {
		t.Fatalf("ratio=%d, want 1500000", got.TrafficRatioScaled)
	}
	if got.BillingEnabled != 1 || got.UserLimitEnabled != 1 {
		t.Fatalf("billing/user_limit=%d/%d, want 1/1", got.BillingEnabled, got.UserLimitEnabled)
	}
	if got.Flags&ruleFlagNeedsQuota == 0 || got.Flags&ruleFlagNeedsCounter == 0 || got.Flags&ruleFlagSNATFixed == 0 || got.Flags&ruleFlagMSSEnabled == 0 {
		t.Fatalf("flags=%b missing expected forwarding flags", got.Flags)
	}
}

func TestRuntimeSemanticHashIgnoresPresentationFields(t *testing.T) {
	base := &runtimeFile{
		Settings: runtimeSettings{Interface: "eth0"},
		Rules: []runtimeRule{{
			ID:             "r1",
			Index:          1,
			UserIndex:      1,
			ListenPort:     10000,
			Protocol:       "tcp",
			IPVersion:      4,
			ResolvedTarget: "198.51.100.8",
			RemotePort:     443,
			TrafficRatio:   1,
			Comment:        "old",
		}},
	}
	next := *base
	next.Rules = append([]runtimeRule{}, base.Rules...)
	next.Rules[0].Comment = "new"
	next.Rules[0].RemoteInput = "example.com"
	left, err := runtimeSemanticHash(base)
	if err != nil {
		t.Fatalf("left hash: %v", err)
	}
	right, err := runtimeSemanticHash(&next)
	if err != nil {
		t.Fatalf("right hash: %v", err)
	}
	if left != right {
		t.Fatalf("hash changed for presentation-only fields: %s != %s", left, right)
	}
}
