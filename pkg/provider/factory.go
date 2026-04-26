package provider

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
)

// errBuildProviderRequired is returned when a multi-tenant factory is queried
// without a configured BuildProvider func.
var errBuildProviderRequired = errors.New("multi-tenant factory: BuildProvider is required")

// Factory produces a per-tenant *ApiProvider. Handlers should call
// ProviderFromContext (or factory.For directly) on every request so they pick
// up the correct provider for the calling tenant.
//
// In legacy single-tenant mode, the factory returns the same singleton
// regardless of input tenant. In multi-tenant OAuth mode (Phase 5+), each
// distinct (TeamID, UserID) gets its own *ApiProvider, cached LRU+TTL.
type Factory interface {
	// For returns the *ApiProvider scoped to the given tenant.
	For(ctx context.Context, t TenantContext) (*ApiProvider, error)
	// Close shuts down all cached providers (best-effort).
	Close() error
}

// ProviderFromContext fetches the ApiProvider for the request's tenant.
// It looks for TenantContext in ctx; if absent (legacy mode), it returns the
// factory's default provider via factory.For(ctx, TenantContext{}).
//
// Handlers that previously captured a singleton at construction time should
// switch to calling this in each handler invocation. In legacy mode this is
// effectively free (returns the singleton); in OAuth mode it returns the
// per-tenant provider.
func ProviderFromContext(ctx context.Context, factory Factory) (*ApiProvider, error) {
	t, _ := TenantFromContext(ctx)
	return factory.For(ctx, t)
}

// legacyFactory wraps a single pre-built *ApiProvider so handlers can use the
// factory API even when running in single-tenant env-var mode.
type legacyFactory struct {
	p *ApiProvider
}

// NewLegacyFactory wraps an existing singleton provider so handlers can use the
// factory API even when running in single-tenant env-var mode. The existing
// main.go path builds one provider and wraps it with this.
func NewLegacyFactory(p *ApiProvider) Factory {
	return &legacyFactory{p: p}
}

func (f *legacyFactory) For(_ context.Context, _ TenantContext) (*ApiProvider, error) {
	return f.p, nil
}

func (f *legacyFactory) Close() error {
	// The legacy ApiProvider has no Close; nothing to do.
	return nil
}

// MultiTenantConfig configures a Factory that builds providers on demand and
// caches them with LRU + idle-TTL eviction.
type MultiTenantConfig struct {
	Logger        *zap.Logger
	MaxEntries    int
	IdleTTL       time.Duration
	BuildProvider func(ctx context.Context, t TenantContext) (*ApiProvider, error)

	// tickFn is an optional test hook. When non-nil, it is called by Start to
	// produce the channel that drives idle-eviction sweeps; tests use this to
	// drive eviction deterministically. When nil, the factory uses
	// time.NewTicker(1 * time.Minute).
	tickFn func() <-chan time.Time
}

const (
	defaultMaxEntries = 256
	defaultIdleTTL    = 30 * time.Minute
	idleSweepInterval = 1 * time.Minute
)

type cacheEntry struct {
	key        string
	tenant     TenantContext
	provider   *ApiProvider
	lastAccess time.Time
}

type multiTenantFactory struct {
	cfg MultiTenantConfig

	mu      sync.Mutex
	entries map[string]*list.Element // key -> list element holding *cacheEntry
	lru     *list.List               // front = most recently used

	// evictor lifecycle
	evictorOnce    sync.Once
	closeOnce      sync.Once
	stopCh         chan struct{}
	evictorStarted bool
}

// NewMultiTenantFactory builds per-tenant providers on demand and caches them
// with an LRU+TTL policy. Idle entries (not used for IdleTTL) are evicted by
// a background goroutine that starts on the first For call and exits on Close.
func NewMultiTenantFactory(cfg MultiTenantConfig) Factory {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = defaultMaxEntries
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = defaultIdleTTL
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	return &multiTenantFactory{
		cfg:     cfg,
		entries: make(map[string]*list.Element),
		lru:     list.New(),
		stopCh:  make(chan struct{}),
	}
}

func tenantKey(t TenantContext) string {
	return t.TeamID + "/" + t.UserID
}

func (f *multiTenantFactory) For(ctx context.Context, t TenantContext) (*ApiProvider, error) {
	f.startEvictorOnce()

	key := tenantKey(t)

	f.mu.Lock()
	if el, ok := f.entries[key]; ok {
		entry := el.Value.(*cacheEntry)
		entry.lastAccess = time.Now()
		f.lru.MoveToFront(el)
		f.mu.Unlock()
		return entry.provider, nil
	}
	f.mu.Unlock()

	// Build outside the lock so concurrent builds for different tenants don't
	// serialize. The trade-off is that two concurrent For calls for the SAME
	// tenant may both build; the loser's provider is discarded after re-check.
	if f.cfg.BuildProvider == nil {
		return nil, errBuildProviderRequired
	}
	p, err := f.cfg.BuildProvider(ctx, t)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Re-check in case another goroutine inserted while we were building.
	if el, ok := f.entries[key]; ok {
		entry := el.Value.(*cacheEntry)
		entry.lastAccess = time.Now()
		f.lru.MoveToFront(el)
		return entry.provider, nil
	}

	entry := &cacheEntry{
		key:        key,
		tenant:     t,
		provider:   p,
		lastAccess: time.Now(),
	}
	el := f.lru.PushFront(entry)
	f.entries[key] = el

	// LRU eviction: drop the oldest until we're at or below MaxEntries.
	for f.lru.Len() > f.cfg.MaxEntries {
		oldest := f.lru.Back()
		if oldest == nil {
			break
		}
		oldEntry := oldest.Value.(*cacheEntry)
		f.lru.Remove(oldest)
		delete(f.entries, oldEntry.key)
		f.cfg.Logger.Debug("multi-tenant factory: LRU evicted entry",
			zap.String("tenant_key", oldEntry.key))
	}

	return p, nil
}

func (f *multiTenantFactory) Close() error {
	f.closeOnce.Do(func() {
		close(f.stopCh)
	})
	return nil
}

func (f *multiTenantFactory) startEvictorOnce() {
	f.evictorOnce.Do(func() {
		var ch <-chan time.Time
		if f.cfg.tickFn != nil {
			ch = f.cfg.tickFn()
		} else {
			t := time.NewTicker(idleSweepInterval)
			ch = t.C
			go func() {
				<-f.stopCh
				t.Stop()
			}()
		}
		f.evictorStarted = true
		go f.evictLoop(ch)
	})
}

func (f *multiTenantFactory) evictLoop(tick <-chan time.Time) {
	for {
		select {
		case <-f.stopCh:
			return
		case <-tick:
			f.sweepIdle()
		}
	}
}

func (f *multiTenantFactory) sweepIdle() {
	cutoff := time.Now().Add(-f.cfg.IdleTTL)

	f.mu.Lock()
	defer f.mu.Unlock()

	for el := f.lru.Back(); el != nil; {
		entry := el.Value.(*cacheEntry)
		if entry.lastAccess.After(cutoff) {
			// Entries are ordered by recency: once we hit a fresh one, all
			// further-front entries are also fresh.
			break
		}
		prev := el.Prev()
		f.lru.Remove(el)
		delete(f.entries, entry.key)
		f.cfg.Logger.Debug("multi-tenant factory: idle evicted entry",
			zap.String("tenant_key", entry.key),
			zap.Time("last_access", entry.lastAccess))
		el = prev
	}
}
