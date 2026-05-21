package main

import (
	"net/netip"
	"testing"
	"time"
)

func testAddr16(t *testing.T, raw string) [16]byte {
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

func testConnKey(t *testing.T) connKey {
	t.Helper()
	return connKey{
		Family:     4,
		Protocol:   6,
		ClientPort: htons(44444),
		ListenPort: htons(38182),
		TargetPort: htons(80),
		ClientAddr: testAddr16(t, "198.51.100.10"),
		ListenAddr: testAddr16(t, "47.79.34.146"),
		TargetAddr: testAddr16(t, "1.1.1.1"),
	}
}

func testConnVal(t *testing.T) connVal {
	t.Helper()
	return connVal{
		RuleID:             2,
		UserID:             0,
		SourceAddr:         testAddr16(t, "47.79.34.146"),
		SourcePort:         htons(40000),
		TrafficRatioScaled: ratioScale,
		BillingEnabled:     1,
	}
}

func testRuleSemantics(t *testing.T) ruleSemantics {
	t.Helper()
	return ruleSemantics{
		RuleID:             2,
		UserID:             0,
		TargetAddr:         testAddr16(t, "1.1.1.1"),
		TargetPort:         htons(80),
		TrafficRatioScaled: ratioScale,
		BillingEnabled:     1,
	}
}

func TestConnectionAllowedByRuntimeWildcardListen(t *testing.T) {
	key := testConnKey(t)
	value := testConnVal(t)
	allowed := map[ruleKey]ruleSemantics{
		testRuleKey(4, 6, 38182, [16]byte{}): testRuleSemantics(t),
	}

	if !connectionAllowedByRuntime(key, value, allowed) {
		t.Fatal("wildcard listen rule should preserve matching connection")
	}
}

func TestConnectionAllowedByRuntimeExactListen(t *testing.T) {
	key := testConnKey(t)
	value := testConnVal(t)
	allowed := map[ruleKey]ruleSemantics{
		testRuleKey(4, 6, 38182, testAddr16(t, "47.79.34.146")): testRuleSemantics(t),
	}

	if !connectionAllowedByRuntime(key, value, allowed) {
		t.Fatal("exact listen rule should preserve matching connection")
	}
}

func TestConnectionAllowedByRuntimeInvalidatesTargetChange(t *testing.T) {
	key := testConnKey(t)
	value := testConnVal(t)
	semantics := testRuleSemantics(t)
	semantics.TargetAddr = testAddr16(t, "1.0.0.1")
	allowed := map[ruleKey]ruleSemantics{
		testRuleKey(4, 6, 38182, [16]byte{}): semantics,
	}

	if connectionAllowedByRuntime(key, value, allowed) {
		t.Fatal("target address change should invalidate connection")
	}
}

func TestConnectionAllowedByRuntimeInvalidatesFixedSNATChange(t *testing.T) {
	key := testConnKey(t)
	value := testConnVal(t)
	semantics := testRuleSemantics(t)
	semantics.SourceAddrFromRule = true
	semantics.SourceAddr = testAddr16(t, "203.0.113.20")
	allowed := map[ruleKey]ruleSemantics{
		testRuleKey(4, 6, 38182, [16]byte{}): semantics,
	}

	if connectionAllowedByRuntime(key, value, allowed) {
		t.Fatal("fixed SNAT source change should invalidate connection")
	}
}

func TestConnectionAllowedByRuntimePreservesFixedSNATMatch(t *testing.T) {
	key := testConnKey(t)
	value := testConnVal(t)
	value.SourceAddr = testAddr16(t, "203.0.113.20")
	semantics := testRuleSemantics(t)
	semantics.SourceAddrFromRule = true
	semantics.SourceAddr = testAddr16(t, "203.0.113.20")
	allowed := map[ruleKey]ruleSemantics{
		testRuleKey(4, 6, 38182, [16]byte{}): semantics,
	}

	if !connectionAllowedByRuntime(key, value, allowed) {
		t.Fatal("unchanged fixed SNAT source should preserve connection")
	}
}

func TestConnectionAllowedByRuntimeInvalidatesTrafficModeChange(t *testing.T) {
	key := testConnKey(t)
	value := testConnVal(t)
	semantics := testRuleSemantics(t)
	semantics.TrafficMode = 1
	allowed := map[ruleKey]ruleSemantics{
		testRuleKey(4, 6, 38182, [16]byte{}): semantics,
	}

	if connectionAllowedByRuntime(key, value, allowed) {
		t.Fatal("traffic mode change should invalidate connection")
	}
}

func TestConnectionAllowedByRuntimeInvalidatesBillingChange(t *testing.T) {
	key := testConnKey(t)
	value := testConnVal(t)
	semantics := testRuleSemantics(t)
	semantics.BillingEnabled = 0
	allowed := map[ruleKey]ruleSemantics{
		testRuleKey(4, 6, 38182, [16]byte{}): semantics,
	}

	if connectionAllowedByRuntime(key, value, allowed) {
		t.Fatal("billing mode change should invalidate connection")
	}
}

func TestElapsedMillis(t *testing.T) {
	start := time.Now().Add(-1500 * time.Millisecond)
	elapsed := elapsedMillis(start)
	if elapsed < 1000 {
		t.Fatalf("elapsedMillis returned %d, want at least 1000", elapsed)
	}
}
