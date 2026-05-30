package main

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func mustAddr16(t *testing.T, raw string) [16]byte {
	t.Helper()
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("parse addr %q: %v", raw, err)
	}
	return addrTo16(addr)
}

func testRuleKey(family uint8, protocol uint8, listenPort uint16, listenAddr [16]byte) ruleKey {
	return ruleKey{
		Family:     family,
		Protocol:   protocol,
		ListenPort: htons(listenPort),
		ListenAddr: listenAddr,
	}
}

func baseConnKey(t *testing.T) connKey {
	t.Helper()
	return connKey{
		Family:     4,
		Protocol:   6,
		ClientPort: htons(44444),
		ListenPort: htons(38182),
		TargetPort: htons(80),
		ClientAddr: mustAddr16(t, "198.51.100.10"),
		ListenAddr: mustAddr16(t, "47.79.34.146"),
		TargetAddr: mustAddr16(t, "1.1.1.1"),
	}
}

func baseConnVal(t *testing.T) connVal {
	t.Helper()
	return connVal{
		RuleID:             2,
		UserID:             0,
		SourceAddr:         mustAddr16(t, "47.79.34.146"),
		SourcePort:         htons(40000),
		TrafficRatioScaled: ratioScale,
		BillingEnabled:     1,
	}
}

func baseRuleSemantics(t *testing.T) ruleSemantics {
	t.Helper()
	return ruleSemantics{
		RuleID:             2,
		UserID:             0,
		TargetAddr:         mustAddr16(t, "1.1.1.1"),
		TargetPort:         htons(80),
		TrafficRatioScaled: ratioScale,
		BillingEnabled:     1,
	}
}

func TestConnectionAllowedByRuntime(t *testing.T) {
	baseKey := baseConnKey(t)
	baseValue := baseConnVal(t)

	tests := []struct {
		name        string
		allowed     func(*testing.T) map[ruleKey]ruleSemantics
		value       func(connVal) connVal
		wantAllowed bool
	}{
		{
			name: "wildcard listen preserves matching connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): baseRuleSemantics(t),
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: true,
		},
		{
			name: "exact listen preserves matching connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, mustAddr16(t, "47.79.34.146")): baseRuleSemantics(t),
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: true,
		},
		{
			name: "target address change invalidates connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.TargetAddr = mustAddr16(t, "1.0.0.1")
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: false,
		},
		{
			name: "fixed snat source change invalidates connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.SourceAddrFromRule = true
				semantics.SourceAddr = mustAddr16(t, "203.0.113.20")
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: false,
		},
		{
			name: "unchanged fixed snat source preserves connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.SourceAddrFromRule = true
				semantics.SourceAddr = mustAddr16(t, "203.0.113.20")
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value: func(value connVal) connVal {
				value.SourceAddr = mustAddr16(t, "203.0.113.20")
				return value
			},
			wantAllowed: true,
		},
		{
			name: "traffic mode change invalidates connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.TrafficMode = 1
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: false,
		},
		{
			name: "billing mode change invalidates connection",
			allowed: func(t *testing.T) map[ruleKey]ruleSemantics {
				semantics := baseRuleSemantics(t)
				semantics.BillingEnabled = 0
				return map[ruleKey]ruleSemantics{
					testRuleKey(4, 6, 38182, [16]byte{}): semantics,
				}
			},
			value:       func(value connVal) connVal { return value },
			wantAllowed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := connectionAllowedByRuntime(baseKey, tc.value(baseValue), tc.allowed(t))
			if got != tc.wantAllowed {
				t.Fatalf("connectionAllowedByRuntime()=%v, want %v", got, tc.wantAllowed)
			}
		})
	}
}

func TestRuleValEquivalentForRefresh(t *testing.T) {
	tests := []struct {
		name     string
		current  ruleVal
		expected ruleVal
		want     bool
	}{
		{
			name: "ignores billing base when billing disabled",
			current: ruleVal{
				RuleID:                   1,
				UserID:                   2,
				TargetPort:               htons(80),
				TrafficRatioScaled:       ratioScale,
				RuleBillingUsedBaseBytes: 100,
				UserBillingUsedBaseBytes: 200,
			},
			expected: ruleVal{
				RuleID:                   1,
				UserID:                   2,
				TargetPort:               htons(80),
				TrafficRatioScaled:       ratioScale,
				RuleBillingUsedBaseBytes: 300,
				UserBillingUsedBaseBytes: 400,
			},
			want: true,
		},
		{
			name: "detects billing base change when billing enabled",
			current: ruleVal{
				RuleID:                   1,
				UserID:                   2,
				TargetPort:               htons(80),
				TrafficRatioScaled:       ratioScale,
				BillingEnabled:           1,
				RuleBillingUsedBaseBytes: 100,
				UserBillingUsedBaseBytes: 200,
			},
			expected: ruleVal{
				RuleID:                   1,
				UserID:                   2,
				TargetPort:               htons(80),
				TrafficRatioScaled:       ratioScale,
				BillingEnabled:           1,
				RuleBillingUsedBaseBytes: 300,
				UserBillingUsedBaseBytes: 400,
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleValEquivalentForRefresh(tc.current, tc.expected)
			if got != tc.want {
				t.Fatalf("ruleValEquivalentForRefresh()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestProtocolSkipPortHelpers(t *testing.T) {
	tests := []struct {
		name             string
		left             []uint16
		right            []uint16
		wantEqual        bool
		wantChangedItems int
	}{
		{
			name:             "same set different order",
			left:             []uint16{443, 80, 8080},
			right:            []uint16{8080, 443, 80},
			wantEqual:        true,
			wantChangedItems: 0,
		},
		{
			name:             "one removed one added",
			left:             []uint16{80, 443},
			right:            []uint16{443, 8080},
			wantEqual:        false,
			wantChangedItems: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := protocolSkipPortsEqual(tc.left, tc.right); got != tc.wantEqual {
				t.Fatalf("protocolSkipPortsEqual()=%v, want %v", got, tc.wantEqual)
			}
			if got := countChangedProtocolSkipPorts(tc.left, tc.right); got != tc.wantChangedItems {
				t.Fatalf("countChangedProtocolSkipPorts()=%d, want %d", got, tc.wantChangedItems)
			}
		})
	}
}

func TestWhitelistHashHelpers(t *testing.T) {
	tests := []struct {
		name             string
		left             []whitelistContentHash
		right            []whitelistContentHash
		wantEqual        bool
		wantChangedItems int
	}{
		{
			name: "same hashes different order",
			left: []whitelistContentHash{
				{Path: "/tmp/b", Hash: "bbb"},
				{Path: "/tmp/a", Hash: "aaa"},
			},
			right: []whitelistContentHash{
				{Path: "/tmp/a", Hash: "aaa"},
				{Path: "/tmp/b", Hash: "bbb"},
			},
			wantEqual:        true,
			wantChangedItems: 0,
		},
		{
			name: "hash update plus file add/remove",
			left: []whitelistContentHash{
				{Path: "/tmp/a", Hash: "aaa"},
				{Path: "/tmp/b", Hash: "bbb"},
			},
			right: []whitelistContentHash{
				{Path: "/tmp/a", Hash: "aaa2"},
				{Path: "/tmp/c", Hash: "ccc"},
			},
			wantEqual:        false,
			wantChangedItems: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := whitelistHashesEqual(tc.left, tc.right); got != tc.wantEqual {
				t.Fatalf("whitelistHashesEqual()=%v, want %v", got, tc.wantEqual)
			}
			if got := countChangedWhitelistHashes(tc.left, tc.right); got != tc.wantChangedItems {
				t.Fatalf("countChangedWhitelistHashes()=%d, want %d", got, tc.wantChangedItems)
			}
		})
	}
}

func TestAuxStateValid(t *testing.T) {
	tests := []struct {
		name    string
		payload statusPayload
		want    bool
	}{
		{
			name:    "empty payload invalid",
			payload: statusPayload{},
			want:    false,
		},
		{
			name:    "matching version valid",
			payload: statusPayload{AuxStateVersion: auxStateVersion},
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := auxStateValid(tc.payload); got != tc.want {
				t.Fatalf("auxStateValid()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestStatusPayloadMarshalsAuxStateAndRefreshDetails(t *testing.T) {
	payload := statusPayload{
		Applied:         true,
		AuxStateVersion: auxStateVersion,
		AuxState: runtimeAuxState{
			GuardEnabled:      true,
			WhitelistEnabled:  true,
			HostEgressEnabled: true,
			BlockTLS:          true,
			ProtocolSkipPorts: []uint16{443, 8443},
			WhitelistHashes: []whitelistContentHash{
				{Path: "/tmp/allow_v4.txt", Hash: "abc"},
			},
		},
		RefreshReport: &refreshReport{
			Mode: "incremental",
			AuxActions: []auxActionSummary{
				{Component: "whitelist", Action: "reuse"},
				{Component: "protocol_skip_ports", Action: "delta-update", ChangedItems: 2},
			},
			AttachTimings: []attachTiming{
				{Component: "xdp", DurationMillis: 3},
			},
		},
	}
	content, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal status payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("unmarshal status payload: %v", err)
	}
	if decoded["aux_state_version"] == nil {
		t.Fatal("aux_state_version missing from JSON payload")
	}
	refreshRaw, ok := decoded["refresh_report"].(map[string]any)
	if !ok {
		t.Fatal("refresh_report missing from JSON payload")
	}
	if _, ok := refreshRaw["aux_actions"]; !ok {
		t.Fatal("refresh_report.aux_actions missing from JSON payload")
	}
	if _, ok := refreshRaw["attach_timings"]; !ok {
		t.Fatal("refresh_report.attach_timings missing from JSON payload")
	}
}

func TestElapsedMillis(t *testing.T) {
	start := time.Now().Add(-1500 * time.Millisecond)
	elapsed := elapsedMillis(start)
	if elapsed < 1000 {
		t.Fatalf("elapsedMillis returned %d, want at least 1000", elapsed)
	}
}
