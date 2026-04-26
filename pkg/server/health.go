package server

import (
	"encoding/json"
	"net/http"

	"github.com/korotovsky/slack-mcp-server/pkg/version"
	"go.uber.org/zap"
)

// HealthzHandler returns an http.HandlerFunc serving an unauthenticated
// liveness probe at /healthz. It always returns HTTP 200 with a small JSON
// payload sourced from pkg/version. This is intentionally decoupled from
// Slack auth and cache readiness so orchestrators can distinguish "process
// alive" from "service ready to take traffic".
func HealthzHandler(logger *zap.Logger) http.HandlerFunc {
	payload := map[string]string{
		"status":      "ok",
		"version":     version.Version,
		"build_time":  version.BuildTime,
		"commit_hash": version.CommitHash,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"status":"ok"}`)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			logger.Debug("healthz write failed",
				zap.String("context", "http"),
				zap.Error(err),
			)
		}
	}
}
