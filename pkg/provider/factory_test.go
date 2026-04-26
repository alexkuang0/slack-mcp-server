package provider

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnitLegacyFactoryReturnsSingleton verifies that the legacy factory
// always returns the wrapped *ApiProvider regardless of the TenantContext.
func TestUnitLegacyFactoryReturnsSingleton(t *testing.T) {
	// A bare *ApiProvider is fine here — we never invoke methods on it. We
	// rely on the factory just returning the pointer it was constructed with.
	singleton := &ApiProvider{}
	f := NewLegacyFactory(singleton)

	ctx := context.Background()

	p1, err := f.For(ctx, TenantContext{})
	require.NoError(t, err)
	p2, err := f.For(ctx, TenantContext{TeamID: "T1", UserID: "U1"})
	require.NoError(t, err)
	p3, err := f.For(ctx, TenantContext{TeamID: "T2", UserID: "U2"})
	require.NoError(t, err)

	assert.Same(t, singleton, p1, "legacy factory must return the same singleton (call 1)")
	assert.Same(t, singleton, p2, "legacy factory must ignore TenantContext (call 2)")
	assert.Same(t, singleton, p3, "legacy factory must ignore TenantContext (call 3)")

	// Close should be a no-op and never error.
	require.NoError(t, f.Close())
}

// TestUnitLegacyFactoryProviderFromContext verifies that ProviderFromContext
// returns the singleton even when no TenantContext is attached (legacy path).
func TestUnitLegacyFactoryProviderFromContext(t *testing.T) {
	singleton := &ApiProvider{}
	f := NewLegacyFactory(singleton)

	got, err := ProviderFromContext(context.Background(), f)
	require.NoError(t, err)
	assert.Same(t, singleton, got)
}

// TestUnitMultiTenantFactoryCachesByKey verifies that repeat For calls for the
// same tenant do not invoke BuildProvider again, while distinct tenants do.
func TestUnitMultiTenantFactoryCachesByKey(t *testing.T) {
	var calls int32
	f := NewMultiTenantFactory(MultiTenantConfig{
		MaxEntries: 8,
		IdleTTL:    time.Hour,
		BuildProvider: func(_ context.Context, _ TenantContext) (*ApiProvider, error) {
			atomic.AddInt32(&calls, 1)
			return &ApiProvider{}, nil
		},
		// Disable real ticker to avoid leaking a goroutine; pass a never-firing channel.
		tickFn: func() <-chan time.Time { return make(chan time.Time) },
	})
	defer f.Close()

	ctx := context.Background()
	tenantA := TenantContext{TeamID: "T1", UserID: "U1"}

	p1, err := f.For(ctx, tenantA)
	require.NoError(t, err)
	p2, err := f.For(ctx, tenantA)
	require.NoError(t, err)
	assert.Same(t, p1, p2, "same tenant must yield same provider")
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "expected one BuildProvider call for one tenant")

	tenantB := TenantContext{TeamID: "T1", UserID: "U2"}
	p3, err := f.For(ctx, tenantB)
	require.NoError(t, err)
	assert.NotSame(t, p1, p3, "different tenants must yield different providers")
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "expected two BuildProvider calls for two tenants")
}

// TestUnitMultiTenantFactoryLRUEviction verifies that exceeding MaxEntries
// evicts the least-recently-used tenant, forcing a rebuild on next access.
func TestUnitMultiTenantFactoryLRUEviction(t *testing.T) {
	var calls int32
	f := NewMultiTenantFactory(MultiTenantConfig{
		MaxEntries: 2,
		IdleTTL:    time.Hour,
		BuildProvider: func(_ context.Context, _ TenantContext) (*ApiProvider, error) {
			atomic.AddInt32(&calls, 1)
			return &ApiProvider{}, nil
		},
		tickFn: func() <-chan time.Time { return make(chan time.Time) },
	})
	defer f.Close()

	ctx := context.Background()
	a := TenantContext{TeamID: "T", UserID: "A"}
	b := TenantContext{TeamID: "T", UserID: "B"}
	c := TenantContext{TeamID: "T", UserID: "C"}

	pA, err := f.For(ctx, a)
	require.NoError(t, err)
	_, err = f.For(ctx, b)
	require.NoError(t, err)
	// A is now LRU; inserting C should evict A.
	_, err = f.For(ctx, c)
	require.NoError(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls), "first three lookups each build once")

	// Re-fetching A must rebuild (was evicted), bringing call count to 4.
	// Re-fetching evicts B (now the LRU) since cap is 2 and current cache is [c, b].
	pA2, err := f.For(ctx, a)
	require.NoError(t, err)
	assert.NotSame(t, pA, pA2, "evicted tenant must yield a freshly built provider")
	assert.Equal(t, int32(4), atomic.LoadInt32(&calls), "evicted tenant rebuilds on next access")

	// C was touched more recently than B before A was re-inserted, so the
	// cache is now [a, c] and B has been evicted. Confirm by re-fetching C
	// (cached, no rebuild) and B (rebuild required).
	_, err = f.For(ctx, c)
	require.NoError(t, err)
	assert.Equal(t, int32(4), atomic.LoadInt32(&calls), "C should still be cached after the LRU dance")

	_, err = f.For(ctx, b)
	require.NoError(t, err)
	assert.Equal(t, int32(5), atomic.LoadInt32(&calls), "B was evicted in the LRU dance and must rebuild")
}

// TestUnitMultiTenantFactoryIdleEviction verifies that entries idle longer
// than IdleTTL are evicted by the background sweep, forcing a rebuild on next
// access. Eviction is driven manually via the tickFn hook to avoid timing flakes.
func TestUnitMultiTenantFactoryIdleEviction(t *testing.T) {
	var calls int32
	tickCh := make(chan time.Time, 1)

	f := NewMultiTenantFactory(MultiTenantConfig{
		MaxEntries: 8,
		IdleTTL:    50 * time.Millisecond,
		BuildProvider: func(_ context.Context, _ TenantContext) (*ApiProvider, error) {
			atomic.AddInt32(&calls, 1)
			return &ApiProvider{}, nil
		},
		tickFn: func() <-chan time.Time { return tickCh },
	})
	defer f.Close()

	ctx := context.Background()
	tenant := TenantContext{TeamID: "T", UserID: "X"}

	p1, err := f.For(ctx, tenant)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))

	// Advance past IdleTTL, then trigger a sweep.
	time.Sleep(75 * time.Millisecond)
	tickCh <- time.Now()

	// Wait for the eviction goroutine to process the tick. We poll the
	// internal map under the mutex via a follow-up For that should rebuild.
	// To make this deterministic, give the goroutine a brief moment to run
	// and then assert via a re-build.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mt := f.(*multiTenantFactory)
		mt.mu.Lock()
		empty := mt.lru.Len() == 0
		mt.mu.Unlock()
		if empty {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	p2, err := f.For(ctx, tenant)
	require.NoError(t, err)
	assert.NotSame(t, p1, p2, "idle-evicted entry must be rebuilt on next access")
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "expected a second BuildProvider call after idle eviction")
}

// TestUnitMultiTenantFactoryDefaults checks that zero-value config fields are
// filled in with sensible defaults.
func TestUnitMultiTenantFactoryDefaults(t *testing.T) {
	f := NewMultiTenantFactory(MultiTenantConfig{
		BuildProvider: func(_ context.Context, _ TenantContext) (*ApiProvider, error) {
			return &ApiProvider{}, nil
		},
		tickFn: func() <-chan time.Time { return make(chan time.Time) },
	})
	defer f.Close()

	mt := f.(*multiTenantFactory)
	assert.Equal(t, defaultMaxEntries, mt.cfg.MaxEntries)
	assert.Equal(t, defaultIdleTTL, mt.cfg.IdleTTL)
	require.NotNil(t, mt.cfg.Logger)
}

// TestUnitMultiTenantFactoryBuildErrorPropagates ensures BuildProvider errors
// surface to callers and the failed entry is not cached.
func TestUnitMultiTenantFactoryBuildErrorPropagates(t *testing.T) {
	wantErr := errBuildProviderRequired // any non-nil error works
	var calls int32
	f := NewMultiTenantFactory(MultiTenantConfig{
		BuildProvider: func(_ context.Context, _ TenantContext) (*ApiProvider, error) {
			atomic.AddInt32(&calls, 1)
			return nil, wantErr
		},
		tickFn: func() <-chan time.Time { return make(chan time.Time) },
	})
	defer f.Close()

	_, err := f.For(context.Background(), TenantContext{TeamID: "T", UserID: "U"})
	require.ErrorIs(t, err, wantErr)

	// Subsequent call should retry (not cached on failure).
	_, err = f.For(context.Background(), TenantContext{TeamID: "T", UserID: "U"})
	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

// TestUnitProviderFromContextWithTenant verifies that a TenantContext attached
// to ctx is forwarded to factory.For.
func TestUnitProviderFromContextWithTenant(t *testing.T) {
	var seenTenant TenantContext
	f := NewMultiTenantFactory(MultiTenantConfig{
		BuildProvider: func(_ context.Context, t TenantContext) (*ApiProvider, error) {
			seenTenant = t
			return &ApiProvider{}, nil
		},
		tickFn: func() <-chan time.Time { return make(chan time.Time) },
	})
	defer f.Close()

	want := TenantContext{TeamID: "TEAM", UserID: "USER", SlackToken: "xoxp-x"}
	ctx := WithTenant(context.Background(), want)

	_, err := ProviderFromContext(ctx, f)
	require.NoError(t, err)
	assert.Equal(t, want, seenTenant)

	// Round-trip through TenantFromContext.
	got, ok := TenantFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, want, got)

	// Empty context yields ok=false.
	_, ok = TenantFromContext(context.Background())
	assert.False(t, ok)
}
