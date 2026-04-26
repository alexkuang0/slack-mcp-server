package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth"
	mcpauthserver "github.com/korotovsky/slack-mcp-server/pkg/mcpauth/server"
	"github.com/korotovsky/slack-mcp-server/pkg/mcpauth/store"
	"github.com/korotovsky/slack-mcp-server/pkg/provider"
	"github.com/korotovsky/slack-mcp-server/pkg/server"
	"github.com/mattn/go-isatty"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var defaultSseHost = "127.0.0.1"
var defaultSsePort = 13080

// Default SQLite DSN for the OAuth store. Operators can override via
// SLACK_MCP_OAUTH_STORAGE_DSN; the default points at /var/lib for Docker
// installs but tests/dev use whatever the operator passes.
const defaultOAuthStorageDSN = "file:/var/lib/slack-mcp/oauth.db?cache=shared&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"

func main() {
	var transport string
	var enabledToolsFlag string
	flag.StringVar(&transport, "t", "stdio", "Transport type (stdio, sse or http)")
	flag.StringVar(&transport, "transport", "stdio", "Transport type (stdio, sse or http)")
	flag.StringVar(&enabledToolsFlag, "e", "", "Comma-separated list of enabled tools (empty = all tools)")
	flag.StringVar(&enabledToolsFlag, "enabled-tools", "", "Comma-separated list of enabled tools (empty = all tools)")
	flag.Parse()

	if enabledToolsFlag == "" {
		enabledToolsFlag = os.Getenv("SLACK_MCP_ENABLED_TOOLS")
	}

	var enabledTools []string
	if enabledToolsFlag != "" {
		for _, tool := range strings.Split(enabledToolsFlag, ",") {
			tool = strings.TrimSpace(tool)
			if tool != "" {
				enabledTools = append(enabledTools, tool)
			}
		}
	}

	logger, err := newLogger(transport)
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	addMessageToolEnv := os.Getenv("SLACK_MCP_ADD_MESSAGE_TOOL")
	err = validateToolConfig(addMessageToolEnv)
	if err != nil {
		logger.Fatal("error in SLACK_MCP_ADD_MESSAGE_TOOL",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	err = server.ValidateEnabledTools(enabledTools)
	if err != nil {
		logger.Fatal("error in SLACK_MCP_ENABLED_TOOLS",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	switch detectMode() {
	case "legacy":
		runLegacy(transport, enabledTools, logger)
	case "oauth":
		runOAuth(transport, enabledTools, logger)
	}
}

// detectMode returns "legacy" when any of the single-tenant token env vars are
// set, or "oauth" otherwise. This is the entry-point switch documented in the
// Phase 5 plan.
func detectMode() string {
	if os.Getenv("SLACK_MCP_XOXP_TOKEN") != "" ||
		os.Getenv("SLACK_MCP_XOXB_TOKEN") != "" ||
		(os.Getenv("SLACK_MCP_XOXC_TOKEN") != "" && os.Getenv("SLACK_MCP_XOXD_TOKEN") != "") {
		return "legacy"
	}
	return "oauth"
}

// runLegacy is the existing single-tenant path: env-derived ApiProvider,
// optional cache warm-up, then ServeStdio/SSE/HTTP.
func runLegacy(transport string, enabledTools []string, logger *zap.Logger) {
	p := provider.New(transport, logger)
	factory := provider.NewLegacyFactory(p)
	s := server.NewMCPServer(factory, logger, enabledTools)

	go func() {
		var once sync.Once

		newUsersWatcher(p, &once, logger)()
		newChannelsWatcher(p, &once, logger)()
	}()

	switch transport {
	case "stdio":
		for {
			if ready, _ := p.IsReady(); ready {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err := s.ServeStdio(); err != nil {
			logger.Fatal("Server error",
				zap.String("context", "console"),
				zap.Error(err),
			)
		}
	case "sse":
		host := os.Getenv("SLACK_MCP_HOST")
		if host == "" {
			host = defaultSseHost
		}
		port := os.Getenv("SLACK_MCP_PORT")
		if port == "" {
			port = strconv.Itoa(defaultSsePort)
		}

		sseServer := s.ServeSSE(":" + port)
		logger.Info(
			fmt.Sprintf("SSE server listening on %s", fmt.Sprintf("%s:%s/sse", host, port)),
			zap.String("context", "console"),
			zap.String("host", host),
			zap.String("port", port),
		)

		if ready, _ := p.IsReady(); !ready {
			logger.Info("Slack MCP Server is still warming up caches",
				zap.String("context", "console"),
			)
		}

		mux := http.NewServeMux()
		mux.Handle("/healthz", server.HealthzHandler(logger))
		mux.Handle("/", sseServer)

		if err := http.ListenAndServe(host+":"+port, mux); err != nil {
			logger.Fatal("Server error",
				zap.String("context", "console"),
				zap.Error(err),
			)
		}
	case "http":
		host := os.Getenv("SLACK_MCP_HOST")
		if host == "" {
			host = defaultSseHost
		}
		port := os.Getenv("SLACK_MCP_PORT")
		if port == "" {
			port = strconv.Itoa(defaultSsePort)
		}

		httpServer := s.ServeHTTP(":" + port)
		logger.Info(
			fmt.Sprintf("HTTP server listening on %s", fmt.Sprintf("%s:%s", host, port)),
			zap.String("context", "console"),
			zap.String("host", host),
			zap.String("port", port),
		)

		if ready, _ := p.IsReady(); !ready {
			logger.Info("Slack MCP Server is still warming up caches",
				zap.String("context", "console"),
			)
		}

		mux := http.NewServeMux()
		mux.Handle("/healthz", server.HealthzHandler(logger))
		mux.Handle("/mcp", httpServer)

		if err := http.ListenAndServe(host+":"+port, mux); err != nil {
			logger.Fatal("Server error",
				zap.String("context", "console"),
				zap.Error(err),
			)
		}
	default:
		logger.Fatal("Invalid transport type",
			zap.String("context", "console"),
			zap.String("transport", transport),
			zap.String("allowed", "stdio, sse, http"),
		)
	}
}

// runOAuth boots the multi-tenant MCP-AS path. Stdio/SSE are disallowed in this
// mode — multi-tenant only makes sense over HTTP.
func runOAuth(transport string, enabledTools []string, logger *zap.Logger) {
	if transport == "stdio" {
		logger.Fatal("OAuth multi-tenant mode does not support stdio transport. Use -t http.",
			zap.String("context", "console"),
		)
	}
	if transport == "sse" {
		logger.Fatal("OAuth multi-tenant mode does not support sse transport. Use -t http.",
			zap.String("context", "console"),
		)
	}

	cfg, err := loadOAuthConfig()
	if err != nil {
		logger.Fatal("OAuth config error",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	storage, err := store.OpenSQLite(context.Background(), cfg.StorageDSN)
	if err != nil {
		logger.Fatal("Failed to open OAuth storage",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	crypto, err := mcpauth.NewCryptoFromBase64(cfg.MasterKeyB64)
	if err != nil {
		logger.Fatal("Failed to initialize OAuth crypto",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	factory := provider.NewMultiTenantFactory(provider.MultiTenantConfig{
		Logger: logger,
		BuildProvider: func(ctx context.Context, t provider.TenantContext) (*provider.ApiProvider, error) {
			if t.SlackToken == "" {
				// Boot-time call from pkg/server.NewMCPServer that resolves
				// the "default" provider for transport/auth-test wiring. No
				// real Slack token is available yet — return a stub. Real
				// per-request paths arrive with t.SlackToken populated by
				// the bearer middleware.
				return provider.NewBootStubProvider(transport, logger), nil
			}
			return provider.NewWithToken(transport, t.SlackToken, logger)
		},
	})

	mcp := server.NewMCPServer(factory, logger, enabledTools)

	asServer := &mcpauthserver.Server{
		Logger: logger,
		Store:  storage,
		Crypto: crypto,
		SlackOAuth: &mcpauth.SlackOAuthConfig{
			ClientID:     cfg.SlackClientID,
			ClientSecret: cfg.SlackClientSecret,
			RedirectURI:  cfg.SlackRedirectURI,
			UserScopes:   cfg.UserScopes,
			BotScopes:    cfg.BotScopes,
		},
		Factory: factory,
		Issuer:  cfg.Issuer,
	}

	host := os.Getenv("SLACK_MCP_HOST")
	if host == "" {
		host = defaultSseHost
	}
	port := os.Getenv("SLACK_MCP_PORT")
	if port == "" {
		port = strconv.Itoa(defaultSsePort)
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", server.HealthzHandler(logger))
	asServer.Mount(mux, mcp.HTTPHandler())

	logger.Info(
		fmt.Sprintf("OAuth multi-tenant HTTP server listening on %s:%s", host, port),
		zap.String("context", "console"),
		zap.String("issuer", cfg.Issuer),
	)
	if err := http.ListenAndServe(host+":"+port, mux); err != nil {
		logger.Fatal("Server error",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}
}

// oauthConfig is the bundle of env-derived configuration for OAuth mode.
type oauthConfig struct {
	SlackClientID     string
	SlackClientSecret string
	SlackRedirectURI  string
	MasterKeyB64      string
	StorageDSN        string
	Issuer            string
	UserScopes        []string
	BotScopes         []string
}

func loadOAuthConfig() (*oauthConfig, error) {
	c := &oauthConfig{
		SlackClientID:     os.Getenv("SLACK_MCP_OAUTH_CLIENT_ID"),
		SlackClientSecret: os.Getenv("SLACK_MCP_OAUTH_CLIENT_SECRET"),
		SlackRedirectURI:  os.Getenv("SLACK_MCP_OAUTH_REDIRECT_URI"),
		MasterKeyB64:      os.Getenv("SLACK_MCP_OAUTH_MASTER_KEY"),
		StorageDSN:        os.Getenv("SLACK_MCP_OAUTH_STORAGE_DSN"),
		Issuer:            os.Getenv("SLACK_MCP_OAUTH_ISSUER"),
	}
	if c.SlackClientID == "" {
		return nil, fmt.Errorf("SLACK_MCP_OAUTH_CLIENT_ID is required in OAuth mode")
	}
	if c.SlackClientSecret == "" {
		return nil, fmt.Errorf("SLACK_MCP_OAUTH_CLIENT_SECRET is required in OAuth mode")
	}
	if c.SlackRedirectURI == "" {
		return nil, fmt.Errorf("SLACK_MCP_OAUTH_REDIRECT_URI is required in OAuth mode")
	}
	if c.MasterKeyB64 == "" {
		return nil, fmt.Errorf("SLACK_MCP_OAUTH_MASTER_KEY is required in OAuth mode")
	}
	if c.Issuer == "" {
		return nil, fmt.Errorf("SLACK_MCP_OAUTH_ISSUER is required in OAuth mode")
	}
	if c.StorageDSN == "" {
		c.StorageDSN = defaultOAuthStorageDSN
	}
	if userScopes := os.Getenv("SLACK_MCP_OAUTH_USER_SCOPES"); userScopes != "" {
		c.UserScopes = splitAndTrim(userScopes)
	}
	if botScopes := os.Getenv("SLACK_MCP_OAUTH_BOT_SCOPES"); botScopes != "" {
		c.BotScopes = splitAndTrim(botScopes)
	}
	return c, nil
}

func splitAndTrim(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func newUsersWatcher(p *provider.ApiProvider, once *sync.Once, logger *zap.Logger) func() {
	return func() {
		logger.Info("Caching users collection...",
			zap.String("context", "console"),
		)

		if os.Getenv("SLACK_MCP_XOXP_TOKEN") == "demo" || (os.Getenv("SLACK_MCP_XOXC_TOKEN") == "demo" && os.Getenv("SLACK_MCP_XOXD_TOKEN") == "demo") {
			logger.Info("Demo credentials are set, skip",
				zap.String("context", "console"),
			)
			return
		}

		err := p.RefreshUsers(context.Background())
		if err != nil {
			logger.Fatal("Error booting provider",
				zap.String("context", "console"),
				zap.Error(err),
			)
		}

		ready, _ := p.IsReady()
		if ready {
			once.Do(func() {
				logger.Info("Slack MCP Server is fully ready",
					zap.String("context", "console"),
				)
			})
		}
	}
}

func newChannelsWatcher(p *provider.ApiProvider, once *sync.Once, logger *zap.Logger) func() {
	return func() {
		logger.Info("Caching channels collection...",
			zap.String("context", "console"),
		)

		if os.Getenv("SLACK_MCP_XOXP_TOKEN") == "demo" || (os.Getenv("SLACK_MCP_XOXC_TOKEN") == "demo" && os.Getenv("SLACK_MCP_XOXD_TOKEN") == "demo") {
			logger.Info("Demo credentials are set, skip.",
				zap.String("context", "console"),
			)
			return
		}

		err := p.RefreshChannels(context.Background())
		if err != nil {
			logger.Fatal("Error booting provider",
				zap.String("context", "console"),
				zap.Error(err),
			)
		}

		ready, _ := p.IsReady()
		if ready {
			once.Do(func() {
				logger.Info("Slack MCP Server is fully ready.",
					zap.String("context", "console"),
				)
			})
		}
	}
}

func validateToolConfig(config string) error {
	if config == "" || config == "true" || config == "1" {
		return nil
	}

	items := strings.Split(config, ",")
	hasNegated := false
	hasPositive := false

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "!") {
			hasNegated = true
		} else {
			hasPositive = true
		}
	}

	if hasNegated && hasPositive {
		return fmt.Errorf("cannot mix allowed and disallowed (! prefixed) channels")
	}

	return nil
}

func newLogger(transport string) (*zap.Logger, error) {
	atomicLevel := zap.NewAtomicLevelAt(zap.InfoLevel)
	if envLevel := os.Getenv("SLACK_MCP_LOG_LEVEL"); envLevel != "" {
		if err := atomicLevel.UnmarshalText([]byte(envLevel)); err != nil {
			fmt.Printf("Invalid log level '%s': %v, using 'info'\n", envLevel, err)
		}
	}

	useJSON := shouldUseJSONFormat()
	useColors := shouldUseColors() && !useJSON

	outputPath := "stdout"
	if transport == "stdio" {
		outputPath = "stderr"
	}

	var config zap.Config

	if useJSON {
		config = zap.Config{
			Level:            atomicLevel,
			Development:      false,
			Encoding:         "json",
			OutputPaths:      []string{outputPath},
			ErrorOutputPaths: []string{"stderr"},
			EncoderConfig: zapcore.EncoderConfig{
				TimeKey:       "timestamp",
				LevelKey:      "level",
				NameKey:       "logger",
				MessageKey:    "message",
				StacktraceKey: "stacktrace",
				EncodeLevel:   zapcore.LowercaseLevelEncoder,
				EncodeTime:    zapcore.RFC3339TimeEncoder,
				EncodeCaller:  zapcore.ShortCallerEncoder,
			},
		}
	} else {
		config = zap.Config{
			Level:            atomicLevel,
			Development:      true,
			Encoding:         "console",
			OutputPaths:      []string{outputPath},
			ErrorOutputPaths: []string{"stderr"},
			EncoderConfig: zapcore.EncoderConfig{
				TimeKey:          "timestamp",
				LevelKey:         "level",
				NameKey:          "logger",
				MessageKey:       "msg",
				StacktraceKey:    "stacktrace",
				EncodeLevel:      getConsoleLevelEncoder(useColors),
				EncodeTime:       zapcore.ISO8601TimeEncoder,
				EncodeCaller:     zapcore.ShortCallerEncoder,
				ConsoleSeparator: " | ",
			},
		}
	}

	logger, err := config.Build(zap.AddCaller())
	if err != nil {
		return nil, err
	}

	logger = logger.With(zap.String("app", "slack-mcp-server"))

	return logger, err
}

// shouldUseJSONFormat determines if JSON format should be used
func shouldUseJSONFormat() bool {
	if format := os.Getenv("SLACK_MCP_LOG_FORMAT"); format != "" {
		return strings.ToLower(format) == "json"
	}

	if env := os.Getenv("ENVIRONMENT"); env != "" {
		switch strings.ToLower(env) {
		case "production", "prod", "staging":
			return true
		case "development", "dev", "local":
			return false
		}
	}

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" ||
		os.Getenv("DOCKER_CONTAINER") != "" ||
		os.Getenv("container") != "" {
		return true
	}

	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return true
	}

	return false
}

func shouldUseColors() bool {
	if colorEnv := os.Getenv("SLACK_MCP_LOG_COLOR"); colorEnv != "" {
		return colorEnv == "true" || colorEnv == "1"
	}

	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}

	if env := os.Getenv("ENVIRONMENT"); env == "development" || env == "dev" {
		return isatty.IsTerminal(os.Stdout.Fd())
	}

	return isatty.IsTerminal(os.Stdout.Fd())
}

func getConsoleLevelEncoder(useColors bool) zapcore.LevelEncoder {
	if useColors {
		return zapcore.CapitalColorLevelEncoder
	}
	return zapcore.CapitalLevelEncoder
}
