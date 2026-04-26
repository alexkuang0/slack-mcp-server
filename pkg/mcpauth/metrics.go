// Package mcpauth — metrics.go
//
// Lightweight, dependency-free counters for the OAuth Authorization Server
// using the stdlib expvar package. Counters are published under the map
// "slack_mcp_oauth" and exposed via the optional /metrics endpoint mounted
// when SLACK_MCP_OAUTH_METRICS=true.
//
// SECURITY: the /metrics endpoint serves expvar.Handler() unauthenticated.
// Operators must keep it behind a firewall, network policy, or reverse proxy.
// This is the same posture as Go's default /debug/vars exposure.
package mcpauth

import (
	"expvar"
	"sync"
)

// metricsMapName is the single expvar.Map name used for OAuth AS counters.
const metricsMapName = "slack_mcp_oauth"

// Counter names. Keep stable — operators wire alerts to them.
const (
	MetricTokensIssuedTotal       = "tokens_issued_total"
	MetricTokensRefreshedTotal    = "tokens_refreshed_total"
	MetricTokensRevokedTotal      = "tokens_revoked_total"
	MetricSlackUnauthorizedTotal  = "slack_unauthorized_total"
	MetricDCRRegistrationsTotal   = "dcr_registrations_total"
	MetricAuthorizeRequestsTotal  = "authorize_requests_total"
	MetricTokenGrantFailuresTotal = "token_grant_failures_total"
)

var (
	metricsOnce sync.Once
	metricsMap  *expvar.Map
)

// Metrics returns the shared expvar.Map for OAuth AS counters. It is
// idempotently created on first call. expvar.Publish panics if the same name
// is published twice; we guard with sync.Once so importing this package
// twice (e.g. by tests in different binaries running in the same process) is
// safe.
func Metrics() *expvar.Map {
	metricsOnce.Do(func() {
		// expvar.NewMap panics on duplicate name; check Get first to make
		// the function safe across re-entry (e.g. test resets in-process).
		if existing := expvar.Get(metricsMapName); existing != nil {
			if m, ok := existing.(*expvar.Map); ok {
				metricsMap = m
				return
			}
		}
		metricsMap = expvar.NewMap(metricsMapName)
	})
	return metricsMap
}

// IncMetric is a small helper that increments a named counter on the shared
// map. Callers prefer this over Metrics().Add(name, 1) so metric names are
// consistent across handlers.
func IncMetric(name string) {
	Metrics().Add(name, 1)
}

// ResetMetricsForTest zeroes every known counter on the shared map. Test-only
// helper — production code should never reset counters.
func ResetMetricsForTest() {
	m := Metrics()
	for _, name := range []string{
		MetricTokensIssuedTotal,
		MetricTokensRefreshedTotal,
		MetricTokensRevokedTotal,
		MetricSlackUnauthorizedTotal,
		MetricDCRRegistrationsTotal,
		MetricAuthorizeRequestsTotal,
		MetricTokenGrantFailuresTotal,
	} {
		// expvar.Map exposes Set for *Var; the simplest reset is to swap in
		// a fresh expvar.Int with value 0.
		m.Set(name, new(expvar.Int))
	}
}
