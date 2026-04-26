package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestUnitHealthzReturnsOK(t *testing.T) {
	handler := HealthzHandler(zap.NewNop())

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "application/json", res.Header.Get("Content-Type"))

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	var parsed map[string]string
	require.NoError(t, json.Unmarshal(body, &parsed))

	assert.Equal(t, "ok", parsed["status"])
	_, hasVersion := parsed["version"]
	assert.True(t, hasVersion, "response body must include a version field")
}
