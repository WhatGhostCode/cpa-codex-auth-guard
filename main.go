// Package main implements the codex-429-autoban CPA plugin.
//
// It auto-disables a Codex credential after a 429 and auto-re-enables it
// once the rate-limit window that was hit has refreshed.
//
// Three capabilities are registered:
//   - usage_plugin: observes every completed request. On a Codex 429 it reads
//     the upstream x-codex-* response headers, decides whether the 5-hour
//     window or the weekly cap was exhausted, and records the exact reset
//     time at which the credential may be used again.
//   - scheduler: on every credential pick, it drops candidates whose recorded
//     reset time has not yet passed (lazy re-enable, since CPA exposes no
//     timer hook) and delegates the actual selection to the built-in
//     round-robin scheduler.
//   - management_api: exposes a small status page and authenticated API for
//     manually clearing the in-memory ban state after the user resets Codex
//     quota or uses a reset card upstream.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	void* call;
	void* free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"codex-auth-guard/cpasdk/pluginabi"
	"codex-auth-guard/cpasdk/pluginapi"
)

const (
	pluginName    = "codex-auth-guard"
	pluginVersion = "0.1.0"

	// providerCodex is the CPA provider key for OpenAI Codex (ChatGPT backend).
	providerCodex = "codex"

	statusUnauthorized    = 401
	statusPaymentRequired = 402
	statusForbidden       = 403
	statusTooManyRequests = 429

	// Codex rate-limit window sizes, in minutes, as reported by the
	// x-codex-primary-window-minutes / x-codex-secondary-window-minutes
	// response headers.
	windowMinutes5h   = 300   // 5 hours
	windowMinutesWeek = 10080 // 7 days

	// usedPercentThreshold is the "this window is the one that tripped" marker.
	// A 429 carries the window that exhausted at ~100% used.
	usedPercentThreshold = 100

	managementRoutePrefix = "/plugins/" + pluginName

	defaultDisabledStatePath = "/CLIProxyAPI/logs/codex-401-autodisable-disabled.json"
	defaultBanStatePath      = "/CLIProxyAPI/logs/codex-429-autoban-bans.json"
	defaultAuthDir           = "/root/.cli-proxy-api"
)

// banStore holds, per credential, the time at which it may be used again.
// A credential is absent from the map when it is not currently banned.
var banStore banState

type banState struct {
	mu            sync.Mutex
	bans          map[string]banEntry // keyed by AuthID
	path          string
	authDir       string
	autoEnable429 bool
	autoDelete429 bool
	loaded        bool
}

type banEntry struct {
	// ResetAt is the upstream-reported time at which the exhausted window
	// refreshes. The credential is skipped until now >= ResetAt.
	ResetAt time.Time `json:"reset_at"`
	// Window is a human-readable label of which limit was hit ("5h" or "week").
	Window string `json:"window"`
	// BannedAt is when the ban was recorded, for logging only.
	BannedAt time.Time `json:"banned_at"`
}

var disabledStore disableState

type disableState struct {
	mu            sync.Mutex
	disabled      map[string]disableEntry
	path          string
	authDir       string
	autoDelete401 bool
	autoDelete402 bool
	autoDelete403 bool
	deleted401    int
	deleted402    int
	deleted403    int
	loaded        bool
}

type disableEntry struct {
	Reason     string    `json:"reason"`
	StatusCode int       `json:"status_code"`
	DisabledAt time.Time `json:"disabled_at"`
}

type persistedDisabledState struct {
	Disabled map[string]disableEntry `json:"disabled"`
	Settings *pluginSettings         `json:"settings,omitempty"`
}
type persistedBanState struct {
	Bans     map[string]banEntry `json:"bans"`
	Settings *pluginSettings     `json:"settings,omitempty"`
}

type pluginSettings struct {
	AutoDelete401 bool  `json:"auto_delete_401,omitempty"`
	AutoDelete402 bool  `json:"auto_delete_402,omitempty"`
	AutoDelete403 bool  `json:"auto_delete_403,omitempty"`
	Deleted401    int   `json:"deleted_401_count,omitempty"`
	Deleted402    int   `json:"deleted_402_count,omitempty"`
	Deleted403    int   `json:"deleted_403_count,omitempty"`
	AutoEnable429 *bool `json:"auto_enable_429,omitempty"`
	AutoDelete429 bool  `json:"auto_delete_429,omitempty"`
}

type pluginConfig struct {
	AuthDir           string `json:"auth_dir"`
	StatePath         string `json:"state_path"`
	DisabledStatePath string `json:"disabled_state_path"`
	BanStatePath      string `json:"ban_state_path"`
	AutoDelete401     *bool  `json:"auto_delete_401"`
	AutoDelete402     *bool  `json:"auto_delete_402"`
	AutoDelete403     *bool  `json:"auto_delete_403"`
	AutoEnable429     *bool  `json:"auto_enable_429"`
	AutoDelete429     *bool  `json:"auto_delete_429"`
}

func applyPluginConfig(raw []byte) {
	if len(raw) == 0 {
		return
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		slog.Warn("codex-429-autoban: failed to decode plugin config", "error", err)
		return
	}
	var cfg pluginConfig
	if rawHost, ok := root["host"]; ok {
		var host pluginConfig
		if err := json.Unmarshal(rawHost, &host); err == nil {
			cfg.AuthDir = host.AuthDir
		}
	}
	for _, key := range []string{"config", "settings", "plugin_config"} {
		if rawCfg, ok := root[key]; ok {
			if err := json.Unmarshal(rawCfg, &cfg); err != nil {
				slog.Warn("codex-429-autoban: failed to decode nested plugin config", "key", key, "error", err)
			}
			break
		}
	}
	var top pluginConfig
	if err := json.Unmarshal(raw, &top); err == nil {
		if strings.TrimSpace(top.AuthDir) != "" {
			cfg.AuthDir = top.AuthDir
		}
		if strings.TrimSpace(top.StatePath) != "" {
			cfg.StatePath = top.StatePath
		}
		if strings.TrimSpace(top.DisabledStatePath) != "" {
			cfg.DisabledStatePath = top.DisabledStatePath
		}
		if strings.TrimSpace(top.BanStatePath) != "" {
			cfg.BanStatePath = top.BanStatePath
		}
		if top.AutoDelete401 != nil {
			cfg.AutoDelete401 = top.AutoDelete401
		}
		if top.AutoDelete402 != nil {
			cfg.AutoDelete402 = top.AutoDelete402
		}
		if top.AutoDelete403 != nil {
			cfg.AutoDelete403 = top.AutoDelete403
		}
		if top.AutoEnable429 != nil {
			cfg.AutoEnable429 = top.AutoEnable429
		}
		if top.AutoDelete429 != nil {
			cfg.AutoDelete429 = top.AutoDelete429
		}
	}
	banStore.applyConfig(cfg)
	disabledStore.applyConfig(cfg)
}

func (s *banState) applyConfig(cfg pluginConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if authDir := strings.TrimSpace(cfg.AuthDir); authDir != "" {
		s.authDir = authDir
	}
	statePath := strings.TrimSpace(cfg.BanStatePath)
	if statePath == "" {
		statePath = strings.TrimSpace(cfg.StatePath)
	}
	if statePath != "" {
		if s.path != statePath {
			s.path = statePath
			s.bans = nil
			s.loaded = false
		}
	}
	if cfg.AutoEnable429 != nil {
		s.autoEnable429 = *cfg.AutoEnable429
	}
	if cfg.AutoDelete429 != nil {
		s.autoDelete429 = *cfg.AutoDelete429
	}
}

func (s *disableState) applyConfig(cfg pluginConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if authDir := strings.TrimSpace(cfg.AuthDir); authDir != "" {
		s.authDir = authDir
	}
	statePath := strings.TrimSpace(cfg.DisabledStatePath)
	if statePath != "" && s.path != statePath {
		s.path = statePath
		s.disabled = nil
		s.loaded = false
	}
	if cfg.AutoDelete401 != nil {
		s.autoDelete401 = *cfg.AutoDelete401
	}
	if cfg.AutoDelete402 != nil {
		s.autoDelete402 = *cfg.AutoDelete402
	}
	if cfg.AutoDelete403 != nil {
		s.autoDelete403 = *cfg.AutoDelete403
	}
}

func (s *banState) ensureLoaded() {
	s.mu.Lock()
	loaded := s.loaded
	s.mu.Unlock()
	if loaded {
		return
	}
	if err := s.loadFromDisk(); err != nil {
		slog.Warn("codex-429-autoban: failed to load ban state", "error", err)
	}
}

func (s *banState) loadFromDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.statePathLocked())
	if err != nil {
		if os.IsNotExist(err) {
			if s.bans == nil {
				s.bans = make(map[string]banEntry)
			}
			s.loaded = true
			return nil
		}
		return err
	}
	var state persistedBanState
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &state); err != nil {
			return err
		}
	}
	if state.Bans == nil {
		state.Bans = make(map[string]banEntry)
	}
	s.bans = state.Bans
	s.autoEnable429 = true
	if state.Settings != nil {
		if state.Settings.AutoEnable429 != nil {
			s.autoEnable429 = *state.Settings.AutoEnable429
		}
		s.autoDelete429 = state.Settings.AutoDelete429
	}
	s.loaded = true
	return nil
}

func (s *banState) statePathLocked() string {
	if strings.TrimSpace(s.path) != "" {
		return s.path
	}
	return defaultBanStatePath
}

func (s *banState) authDirLocked() string {
	if strings.TrimSpace(s.authDir) != "" {
		return s.authDir
	}
	return defaultAuthDir
}

func (s *banState) saveLocked() error {
	if s.bans == nil {
		s.bans = make(map[string]banEntry)
	}
	path := s.statePathLocked()
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(persistedBanState{Bans: s.bans, Settings: &pluginSettings{AutoEnable429: boolPtr(s.autoEnable429), AutoDelete429: s.autoDelete429}}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

// lookup returns the ban entry for the given auth ID and whether one exists.
func (s *banState) lookup(authID string) (banEntry, bool) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.bans[authID]
	return e, ok
}

// set records a ban for the given auth ID.
func (s *banState) set(authID string, e banEntry) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bans == nil {
		s.bans = make(map[string]banEntry)
	}
	if e.BannedAt.IsZero() {
		e.BannedAt = time.Now()
	}
	s.bans[authID] = e
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-429-autoban: failed to save ban state", "error", err)
	}
}

// clearIfExpired removes the ban for authID if its reset time has passed.
// Returns whether the credential is currently banned AFTER this check.
func (s *banState) clearIfExpired(authID string, now time.Time) (stillBanned bool) {
	s.ensureLoaded()
	s.mu.Lock()
	e, ok := s.bans[authID]
	if !ok {
		s.mu.Unlock()
		return false
	}
	if !s.autoEnable429 {
		s.mu.Unlock()
		return true
	}
	if now.Before(e.ResetAt) {
		s.mu.Unlock()
		return true
	}
	delete(s.bans, authID)
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-429-autoban: failed to save ban state", "error", err)
	}
	s.mu.Unlock()
	if err := s.setAuthFileDisabled(authID, false); err != nil {
		slog.Warn("codex-429-autoban: failed to mark auth file enabled", "auth_id", authID, "error", err)
	}
	slog.Info("codex-429-autoban: auto re-enabled credential", "auth_id", authID, "window", e.Window, "reset_at", e.ResetAt.Format(time.RFC3339))
	return false
}

// clearExpired removes every ban whose reset time has passed.
func (s *banState) clearExpired(now time.Time) int {
	s.ensureLoaded()
	s.mu.Lock()
	if !s.autoEnable429 {
		s.mu.Unlock()
		return 0
	}
	removed := make(map[string]banEntry)
	for authID, e := range s.bans {
		if !now.Before(e.ResetAt) {
			delete(s.bans, authID)
			removed[authID] = e
		}
	}
	if len(removed) > 0 {
		if err := s.saveLocked(); err != nil {
			slog.Warn("codex-429-autoban: failed to save ban state", "error", err)
		}
	}
	s.mu.Unlock()
	for authID, e := range removed {
		if err := s.setAuthFileDisabled(authID, false); err != nil {
			slog.Warn("codex-429-autoban: failed to mark auth file enabled", "auth_id", authID, "error", err)
		}
		slog.Info("codex-429-autoban: auto re-enabled credential", "auth_id", authID, "window", e.Window, "reset_at", e.ResetAt.Format(time.RFC3339))
	}
	return len(removed)
}

// clear removes the ban for authID, if present.
func (s *banState) clear(authID string) (banEntry, bool) {
	s.ensureLoaded()
	s.mu.Lock()
	if s.bans == nil {
		s.mu.Unlock()
		return banEntry{}, false
	}
	e, ok := s.bans[authID]
	if ok {
		delete(s.bans, authID)
		if err := s.saveLocked(); err != nil {
			slog.Warn("codex-429-autoban: failed to save ban state", "error", err)
		}
	}
	s.mu.Unlock()
	if ok {
		if err := s.setAuthFileDisabled(authID, false); err != nil {
			slog.Warn("codex-429-autoban: failed to mark auth file enabled", "auth_id", authID, "error", err)
		}
	}
	return e, ok
}

func (s *banState) removeStateOnly(authID string) (banEntry, bool) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bans == nil {
		return banEntry{}, false
	}
	e, ok := s.bans[authID]
	if ok {
		delete(s.bans, authID)
		if err := s.saveLocked(); err != nil {
			slog.Warn("codex-429-autoban: failed to save ban state", "error", err)
		}
	}
	return e, ok
}

func (s *banState) clearAllStateOnly() int {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.bans)
	s.bans = make(map[string]banEntry)
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-429-autoban: failed to save ban state", "error", err)
	}
	return n
}

// clearAll removes every active ban and returns how many were removed.
func (s *banState) clearAll() int {
	s.ensureLoaded()
	s.mu.Lock()
	snapshot := make([]string, 0, len(s.bans))
	for authID := range s.bans {
		snapshot = append(snapshot, authID)
	}
	s.bans = make(map[string]banEntry)
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-429-autoban: failed to save ban state", "error", err)
	}
	s.mu.Unlock()
	for _, authID := range snapshot {
		if err := s.setAuthFileDisabled(authID, false); err != nil {
			slog.Warn("codex-429-autoban: failed to mark auth file enabled", "auth_id", authID, "error", err)
		}
	}
	return len(snapshot)
}

// snapshot returns a copy of the current bans for diagnostics / management UI.
func (s *banState) snapshot() map[string]banEntry {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]banEntry, len(s.bans))
	for authID, e := range s.bans {
		out[authID] = e
	}
	return out
}

func boolPtr(v bool) *bool { return &v }

func (s *banState) autoDeleteEnabled() bool {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.autoDelete429
}

func (s *banState) setAutoEnable429(enabled bool) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoEnable429 = enabled
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-429-autoban: failed to save settings", "error", err)
	}
}

func (s *banState) setAutoDelete429(enabled bool) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoDelete429 = enabled
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-429-autoban: failed to save settings", "error", err)
	}
}

func (s *banState) settingsSnapshot() managementSettings {
	return currentManagementSettings()
}

func (s *banState) authFilePath(authID string) (string, error) {
	authID = strings.TrimSpace(authID)
	if authID == "" || filepath.Base(authID) != authID || strings.ContainsAny(authID, "/\\") || !strings.HasSuffix(authID, ".json") {
		return "", fmt.Errorf("invalid auth_id: %s", authID)
	}
	s.mu.Lock()
	dir := s.authDirLocked()
	s.mu.Unlock()
	return filepath.Join(dir, authID), nil
}

func (s *banState) setAuthFileDisabled(authID string, disabled bool) error {
	path, err := s.authFilePath(authID)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return err
	}
	body["disabled"] = disabled
	raw, err = json.Marshal(body)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

func (s *banState) deleteAuthFile(authID string) (bool, error) {
	path, err := s.authFilePath(authID)
	if err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *banState) markLoadedAuthFilesDisabled() {
	for authID := range s.snapshot() {
		if err := s.setAuthFileDisabled(authID, true); err != nil {
			slog.Warn("codex-429-autoban: failed to mark auth file disabled", "auth_id", authID, "error", err)
		}
	}
}

func main() {}

// cliproxy_plugin_init is the native entry point CPA calls when loading the
// plugin. It wires the host reverse-call API and registers our call/free/shutdown
// function pointers.
//
//export cliproxy_plugin_init
func cliproxy_plugin_init(_ *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

// cliproxyPluginCall is the single dispatch entry CPA invokes for every method.
//
//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

// handleMethod routes a CPA method to its handler.
func (s *disableState) ensureLoaded() {
	s.mu.Lock()
	loaded := s.loaded
	s.mu.Unlock()
	if loaded {
		return
	}
	if err := s.loadFromDisk(); err != nil {
		slog.Warn("codex-auth-guard: failed to load disabled state", "error", err)
	}
}

func (s *disableState) loadFromDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.statePathLocked())
	if err != nil {
		if os.IsNotExist(err) {
			if s.disabled == nil {
				s.disabled = make(map[string]disableEntry)
			}
			s.loaded = true
			return nil
		}
		return err
	}
	var state persistedDisabledState
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &state); err != nil {
			return err
		}
	}
	if state.Disabled == nil {
		state.Disabled = make(map[string]disableEntry)
	}
	s.disabled = state.Disabled
	if state.Settings != nil {
		s.autoDelete401 = state.Settings.AutoDelete401
		s.autoDelete402 = state.Settings.AutoDelete402
		s.autoDelete403 = state.Settings.AutoDelete403
		s.deleted401 = state.Settings.Deleted401
		s.deleted402 = state.Settings.Deleted402
		s.deleted403 = state.Settings.Deleted403
	}
	s.loaded = true
	return nil
}

func (s *disableState) statePathLocked() string {
	if strings.TrimSpace(s.path) != "" {
		return s.path
	}
	return defaultDisabledStatePath
}

func (s *disableState) authDirLocked() string {
	if strings.TrimSpace(s.authDir) != "" {
		return s.authDir
	}
	return defaultAuthDir
}

func (s *disableState) saveLocked() error {
	if s.disabled == nil {
		s.disabled = make(map[string]disableEntry)
	}
	state := persistedDisabledState{Disabled: s.disabled, Settings: &pluginSettings{AutoDelete401: s.autoDelete401, AutoDelete402: s.autoDelete402, AutoDelete403: s.autoDelete403, Deleted401: s.deleted401, Deleted402: s.deleted402, Deleted403: s.deleted403}}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := s.statePathLocked()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

func (s *disableState) lookup(authID string) (disableEntry, bool) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.disabled[authID]
	return entry, ok
}

func (s *disableState) set(authID string, e disableEntry) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.disabled == nil {
		s.disabled = make(map[string]disableEntry)
	}
	if e.DisabledAt.IsZero() {
		e.DisabledAt = time.Now()
	}
	s.disabled[authID] = e
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-auth-guard: failed to save disabled state", "error", err)
	}
}

func (s *disableState) clear(authID string) (disableEntry, bool) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.disabled[authID]
	if !ok {
		return disableEntry{}, false
	}
	delete(s.disabled, authID)
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-auth-guard: failed to save disabled state", "error", err)
	}
	return entry, true
}

func (s *disableState) clearAll() int {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.disabled)
	s.disabled = make(map[string]disableEntry)
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-auth-guard: failed to save disabled state", "error", err)
	}
	return count
}

func (s *disableState) snapshot() map[string]disableEntry {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]disableEntry, len(s.disabled))
	for authID, entry := range s.disabled {
		out[authID] = entry
	}
	return out
}

func (s *disableState) autoDeleteEnabled(statusCode int) bool {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch statusCode {
	case statusUnauthorized:
		return s.autoDelete401
	case statusPaymentRequired:
		return s.autoDelete402
	case statusForbidden:
		return s.autoDelete403
	default:
		return false
	}
}

func (s *disableState) setAutoDeleteStatus(statusCode int, enabled bool) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch statusCode {
	case statusUnauthorized:
		s.autoDelete401 = enabled
	case statusPaymentRequired:
		s.autoDelete402 = enabled
	case statusForbidden:
		s.autoDelete403 = enabled
	}
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-auth-guard: failed to save disabled settings", "error", err)
	}
}

func (s *disableState) incrementDeletedCount(statusCode int) {
	s.ensureLoaded()
	s.mu.Lock()
	defer s.mu.Unlock()
	switch statusCode {
	case statusUnauthorized:
		s.deleted401++
	case statusPaymentRequired:
		s.deleted402++
	case statusForbidden:
		s.deleted403++
	default:
		return
	}
	if err := s.saveLocked(); err != nil {
		slog.Warn("codex-auth-guard: failed to save deleted count", "status_code", statusCode, "error", err)
	}
}

func (s *disableState) authFilePath(authID string) (string, error) {
	authID = strings.TrimSpace(authID)
	if authID == "" || filepath.Base(authID) != authID || strings.ContainsAny(authID, "/\\") || !strings.HasSuffix(authID, ".json") {
		return "", fmt.Errorf("invalid auth_id: %s", authID)
	}
	s.mu.Lock()
	dir := s.authDirLocked()
	s.mu.Unlock()
	return filepath.Join(dir, authID), nil
}

func (s *disableState) setAuthFileDisabled(authID string, disabled bool) error {
	path, err := s.authFilePath(authID)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return err
	}
	body["disabled"] = disabled
	raw, err = json.Marshal(body)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

func (s *disableState) deleteAuthFile(authID string) (bool, error) {
	path, err := s.authFilePath(authID)
	if err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *disableState) markLoadedAuthFilesDisabled() {
	for authID := range s.snapshot() {
		if err := s.setAuthFileDisabled(authID, true); err != nil {
			slog.Warn("codex-auth-guard: failed to mark disabled auth file", "auth_id", authID, "error", err)
		}
	}
}
func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		applyPluginConfig(request)
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodUsageHandle:
		return handleUsage(request)
	case pluginabi.MethodSchedulerPick:
		return handleSchedulerPick(request)
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration())
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// pluginRegistration declares the plugin's metadata and capabilities.
// Both usage_plugin and scheduler must be true.
func pluginRegistration() registration {
	banStore.ensureLoaded()
	banStore.clearExpired(time.Now())
	banStore.markLoadedAuthFilesDisabled()
	disabledStore.ensureLoaded()
	disabledStore.markLoadedAuthFilesDisabled()
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "local",
			GitHubRepository: "https://github.com/router-for-me/CLIProxyAPI",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "auth_dir", Type: pluginapi.ConfigFieldTypeString, Description: "Directory containing CPA auth JSON files."},
				{Name: "disabled_state_path", Type: pluginapi.ConfigFieldTypeString, Description: "Path to the persisted 401/402/403 disabled state JSON file."},
				{Name: "ban_state_path", Type: pluginapi.ConfigFieldTypeString, Description: "Path to the persisted 429 ban state JSON file."},
				{Name: "auto_delete_401", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Delete a Codex auth JSON immediately when it returns 401."},
				{Name: "auto_delete_402", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Delete a Codex auth JSON immediately when it returns 402."},
				{Name: "auto_delete_403", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Delete a Codex auth JSON immediately when it returns 403."},
				{Name: "auto_enable_429", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Automatically re-enable Codex auth JSON when a 429 reset time has passed."},
				{Name: "auto_delete_429", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Delete a Codex auth JSON immediately when it returns 429."},
			},
		},
		Capabilities: registrationCapability{
			UsagePlugin:   true,
			Scheduler:     true,
			ManagementAPI: true,
		},
	}
}

func isCredentialDisableStatus(statusCode int) bool {
	switch statusCode {
	case statusUnauthorized, statusPaymentRequired, statusForbidden:
		return true
	default:
		return false
	}
}

func credentialDisableReason(statusCode int) string {
	text := http.StatusText(statusCode)
	if text == "" {
		return strconv.Itoa(statusCode)
	}
	return strconv.Itoa(statusCode) + " " + text
}

// handleUsage observes completed Codex requests and applies the corresponding guard.
func handleUsage(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return okEnvelope(map[string]any{})
	}
	var record pluginapi.UsageRecord
	if errUnmarshal := json.Unmarshal(raw, &record); errUnmarshal != nil {
		slog.Warn("codex-auth-guard: failed to decode usage record", "error", errUnmarshal)
		return okEnvelope(map[string]any{})
	}
	if !strings.EqualFold(record.Provider, providerCodex) || !record.Failed {
		return okEnvelope(map[string]any{})
	}
	authID := strings.TrimSpace(record.AuthID)
	if authID == "" {
		slog.Warn("codex-auth-guard: failed Codex usage has empty AuthID", "status_code", record.Failure.StatusCode)
		return okEnvelope(map[string]any{})
	}

	if isCredentialDisableStatus(record.Failure.StatusCode) {
		if disabledStore.autoDeleteEnabled(record.Failure.StatusCode) {
			deleted, err := disabledStore.deleteAuthFile(authID)
			if err != nil {
				slog.Warn("codex-auth-guard: failed to auto-delete auth file after credential-disable status", "auth_id", authID, "status_code", record.Failure.StatusCode, "error", err)
			} else if deleted {
				disabledStore.clear(authID)
				disabledStore.incrementDeletedCount(record.Failure.StatusCode)
				slog.Warn("codex-auth-guard: auto-deleted credential after credential-disable status", "auth_id", authID, "status_code", record.Failure.StatusCode)
			}
			return okEnvelope(map[string]any{})
		}
		disabledStore.set(authID, disableEntry{Reason: credentialDisableReason(record.Failure.StatusCode), StatusCode: record.Failure.StatusCode})
		if err := disabledStore.setAuthFileDisabled(authID, true); err != nil {
			slog.Warn("codex-auth-guard: failed to mark auth file disabled", "auth_id", authID, "error", err)
		}
		slog.Warn("codex-auth-guard: disabled credential after credential-disable status", "auth_id", authID, "status_code", record.Failure.StatusCode)
		return okEnvelope(map[string]any{})
	}

	if record.Failure.StatusCode != statusTooManyRequests {
		return okEnvelope(map[string]any{})
	}

	entry, ok := classifyAndBuildBan(record.ResponseHeaders)
	if !ok {
		now := time.Now()
		entry = banEntry{ResetAt: now.Add(5 * time.Hour), Window: "5h (fallback, headers missing)", BannedAt: now}
		slog.Warn("codex-auth-guard: x-codex-* headers missing on 429, falling back to 5h ban", "auth_id", authID)
	} else {
		entry.BannedAt = time.Now()
	}
	if banStore.autoDeleteEnabled() {
		deleted, err := banStore.deleteAuthFile(authID)
		if err != nil {
			slog.Warn("codex-auth-guard: failed to auto-delete auth file after 429", "auth_id", authID, "error", err)
		} else if deleted {
			banStore.clear(authID)
			slog.Warn("codex-auth-guard: auto-deleted credential after 429", "auth_id", authID)
		}
		return okEnvelope(map[string]any{})
	}
	banStore.set(authID, entry)
	if err := banStore.setAuthFileDisabled(authID, true); err != nil {
		slog.Warn("codex-auth-guard: failed to mark auth file disabled", "auth_id", authID, "error", err)
	}
	slog.Info("codex-auth-guard: banned credential after 429", "auth_id", authID, "window", entry.Window, "reset_at", entry.ResetAt.Format(time.RFC3339))
	return okEnvelope(map[string]any{})
}
func classifyAndBuildBan(headers http.Header) (banEntry, bool) {
	h := headers

	primaryUsed := headerFloat(h, "x-codex-primary-used-percent")
	secondaryUsed := headerFloat(h, "x-codex-secondary-used-percent")
	primaryReset := headerUnixTime(h, "x-codex-primary-reset-at")
	secondaryReset := headerUnixTime(h, "x-codex-secondary-reset-at")

	// Prefer the explicit "which window is full" signal: the window whose
	// used-percent reached the threshold. If both are present, pick the one
	// at threshold; if only one header family is present, use that.
	primaryFull := primaryUsed >= usedPercentThreshold
	secondaryFull := secondaryUsed >= usedPercentThreshold

	switch {
	case secondaryFull && !primaryFull:
		if !secondaryReset.IsZero() {
			return banEntry{ResetAt: secondaryReset, Window: "week"}, true
		}
	case primaryFull && !secondaryFull:
		if !primaryReset.IsZero() {
			return banEntry{ResetAt: primaryReset, Window: "5h"}, true
		}
	case primaryFull && secondaryFull:
		// Both exhausted: must wait for the later reset (weekly) to be safe.
		if !secondaryReset.IsZero() {
			return banEntry{ResetAt: secondaryReset, Window: "week (both full)"}, true
		}
		if !primaryReset.IsZero() {
			return banEntry{ResetAt: primaryReset, Window: "5h (both full, weekly reset missing)"}, true
		}
	default:
		// Neither reports as full via used-percent. Fall back to window-minutes
		// identity if a reset time is present, else give up.
		if !primaryReset.IsZero() && headerInt(h, "x-codex-primary-window-minutes") == windowMinutes5h {
			return banEntry{ResetAt: primaryReset, Window: "5h"}, true
		}
		if !secondaryReset.IsZero() && headerInt(h, "x-codex-secondary-window-minutes") == windowMinutesWeek {
			return banEntry{ResetAt: secondaryReset, Window: "week"}, true
		}
	}
	return banEntry{}, false
}

// handleSchedulerPick filters out credentials that are still banned, then
// delegates the actual selection to the built-in round-robin scheduler.
func handleSchedulerPick(raw []byte) ([]byte, error) {
	var req pluginapi.SchedulerPickRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	now := time.Now()
	available := make([]pluginapi.SchedulerAuthCandidate, 0, len(req.Candidates))
	dropped := false
	for _, candidate := range req.Candidates {
		if !strings.EqualFold(candidate.Provider, providerCodex) {
			available = append(available, candidate)
			continue
		}
		if _, disabled := disabledStore.lookup(candidate.ID); disabled {
			dropped = true
			continue
		}
		if banStore.clearIfExpired(candidate.ID, now) {
			dropped = true
			continue
		}
		available = append(available, candidate)
	}

	if len(available) == 0 {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: dropped})
	}
	if len(available) == len(req.Candidates) {
		return okEnvelope(pluginapi.SchedulerPickResponse{DelegateBuiltin: pluginapi.SchedulerBuiltinRoundRobin, Handled: true})
	}
	chosen := available[0]
	for _, c := range available[1:] {
		if c.Priority > chosen.Priority {
			chosen = c
		}
	}
	return okEnvelope(pluginapi.SchedulerPickResponse{AuthID: chosen.ID, Handled: true})
}

// managementRegistration exposes a small Management API and resource page so
// users can put an auth back into the pool after manually resetting Codex
// quota or using a reset card. CPA does not provide a timer/event for that
// upstream-side action, so manual unban is the reliable integration point.
func managementRegistration() pluginapi.ManagementRegistrationResponse {
	return pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: http.MethodGet, Path: managementRoutePrefix + "/disabled", Description: "List Codex auths disabled by 401/402/403."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/enable", Description: "Remove one Codex auth from the 401/402/403 disabled list."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/enable-all", Description: "Remove every Codex auth from the 401/402/403 disabled list."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/delete-disabled", Description: "Delete one auth JSON file from the 401/402/403 disabled list."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/delete-all-disabled", Description: "Delete every auth JSON file from the 401/402/403 disabled list."},
			{Method: http.MethodGet, Path: managementRoutePrefix + "/bans", Description: "List Codex auths held out of the pool by 429."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/unban", Description: "Remove one Codex auth from the 429 ban list."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/unban-all", Description: "Remove every Codex auth from the 429 ban list."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/delete-ban", Description: "Delete one auth JSON file from the 429 ban list."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/delete-all-bans", Description: "Delete every auth JSON file from the 429 ban list."},
			{Method: http.MethodGet, Path: managementRoutePrefix + "/settings", Description: "Read codex-auth-guard settings."},
			{Method: http.MethodPost, Path: managementRoutePrefix + "/settings", Description: "Update codex-auth-guard settings."},
		},
		Resources: []pluginapi.ResourceRoute{{Path: "/status", Menu: "Codex Auth Guard", Description: "View 401/402/403 disabled credentials and 429 bans."}},
	}
}
func handleManagement(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return okEnvelope(dispatchManagement(req))
}

func dispatchManagement(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	switch {
	case method == http.MethodGet && matchesManagementPath(req.Path, "/disabled"):
		return jsonManagementResponse(http.StatusOK, currentDisabledStatus())
	case method == http.MethodPost && matchesManagementPath(req.Path, "/enable"):
		return handleManagementEnable(req)
	case method == http.MethodPost && matchesManagementPath(req.Path, "/enable-all"):
		return handleManagementEnableAll()
	case method == http.MethodPost && matchesManagementPath(req.Path, "/delete-disabled"):
		return handleManagementDeleteDisabled(req)
	case method == http.MethodPost && matchesManagementPath(req.Path, "/delete-all-disabled"):
		return handleManagementDeleteAllDisabled()
	case method == http.MethodGet && matchesManagementPath(req.Path, "/bans"):
		return jsonManagementResponse(http.StatusOK, currentBanStatus())
	case method == http.MethodPost && matchesManagementPath(req.Path, "/unban"):
		return handleManagementUnban(req)
	case method == http.MethodPost && matchesManagementPath(req.Path, "/unban-all"):
		return handleManagementUnbanAll()
	case method == http.MethodPost && matchesManagementPath(req.Path, "/delete-ban"):
		return handleManagementDeleteBan(req)
	case method == http.MethodPost && matchesManagementPath(req.Path, "/delete-all-bans"):
		return handleManagementDeleteAllBans()
	case method == http.MethodGet && matchesManagementPath(req.Path, "/settings"):
		return jsonManagementResponse(http.StatusOK, currentManagementSettings())
	case method == http.MethodPost && matchesManagementPath(req.Path, "/settings"):
		return handleManagementSettings(req)
	case method == http.MethodGet && matchesResourcePath(req.Path, "/status"):
		return htmlManagementResponse(http.StatusOK, managementStatusPage())
	default:
		return jsonManagementResponse(http.StatusNotFound, map[string]any{"error": "not_found", "path": req.Path, "method": method})
	}
}

type managementBanStatus struct {
	Plugin  string              `json:"plugin"`
	Version string              `json:"version"`
	Count   int                 `json:"count"`
	Bans    []managementBanInfo `json:"bans"`
}

type managementBanInfo struct {
	AuthID           string `json:"auth_id"`
	Window           string `json:"window"`
	BannedAt         string `json:"banned_at,omitempty"`
	BannedAtUnix     int64  `json:"banned_at_unix,omitempty"`
	ResetAt          string `json:"reset_at"`
	ResetAtUnix      int64  `json:"reset_at_unix"`
	RemainingSeconds int64  `json:"remaining_seconds"`
	AuthIndex        string `json:"auth_index,omitempty"`
}

type managementDisabledStatus struct {
	Plugin   string                   `json:"plugin"`
	Version  string                   `json:"version"`
	Count    int                      `json:"count"`
	Disabled []managementDisabledInfo `json:"disabled"`
}

type managementDisabledInfo struct {
	AuthID         string `json:"auth_id"`
	Reason         string `json:"reason"`
	StatusCode     int    `json:"status_code"`
	DisabledAt     string `json:"disabled_at,omitempty"`
	DisabledAtUnix int64  `json:"disabled_at_unix,omitempty"`
}

func currentDisabledStatus() managementDisabledStatus {
	snapshot := disabledStore.snapshot()
	items := make([]managementDisabledInfo, 0, len(snapshot))
	for authID, entry := range snapshot {
		info := managementDisabledInfo{AuthID: authID, Reason: entry.Reason, StatusCode: entry.StatusCode}
		if !entry.DisabledAt.IsZero() {
			info.DisabledAt = entry.DisabledAt.Format(time.RFC3339)
			info.DisabledAtUnix = entry.DisabledAt.Unix()
		}
		items = append(items, info)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].AuthID < items[j].AuthID })
	return managementDisabledStatus{Plugin: pluginName, Version: pluginVersion, Count: len(items), Disabled: items}
}

type managementAuthRequest struct {
	AuthID string `json:"auth_id"`
	All    bool   `json:"all"`
}

func handleManagementEnable(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body managementAuthRequest
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "invalid_json", "message": err.Error()})
		}
	}
	if strings.EqualFold(req.Query.Get("all"), "true") || body.All {
		return handleManagementEnableAll()
	}
	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		authID = strings.TrimSpace(req.Query.Get("auth_id"))
	}
	if authID == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "missing_auth_id", "message": "provide auth_id in JSON body or query string"})
	}
	if err := disabledStore.setAuthFileDisabled(authID, false); err != nil {
		slog.Warn("codex-auth-guard: failed to mark auth file enabled", "auth_id", authID, "error", err)
	}
	_, removed := disabledStore.clear(authID)
	return jsonManagementResponse(http.StatusOK, map[string]any{"ok": true, "auth_id": authID, "removed": removed, "status": currentDisabledStatus()})
}

func handleManagementEnableAll() pluginapi.ManagementResponse {
	snapshot := disabledStore.snapshot()
	for authID := range snapshot {
		if err := disabledStore.setAuthFileDisabled(authID, false); err != nil {
			slog.Warn("codex-auth-guard: failed to mark auth file enabled", "auth_id", authID, "error", err)
		}
	}
	removed := disabledStore.clearAll()
	return jsonManagementResponse(http.StatusOK, map[string]any{"ok": true, "removed": removed, "status": currentDisabledStatus()})
}

func handleManagementDeleteDisabled(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body managementAuthRequest
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "invalid_json", "message": err.Error()})
		}
	}
	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		authID = strings.TrimSpace(req.Query.Get("auth_id"))
	}
	if authID == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "missing_auth_id", "message": "provide auth_id in JSON body or query string"})
	}
	deleted, err := disabledStore.deleteAuthFile(authID)
	if err != nil {
		return jsonManagementResponse(http.StatusInternalServerError, map[string]any{"error": "delete_failed", "message": err.Error(), "auth_id": authID})
	}
	_, removed := disabledStore.clear(authID)
	return jsonManagementResponse(http.StatusOK, map[string]any{"ok": true, "auth_id": authID, "deleted": deleted, "removed": removed, "status": currentDisabledStatus()})
}

func handleManagementDeleteAllDisabled() pluginapi.ManagementResponse {
	snapshot := disabledStore.snapshot()
	deleted := 0
	errors := make([]map[string]string, 0)
	for authID := range snapshot {
		fileDeleted, err := disabledStore.deleteAuthFile(authID)
		if err != nil {
			errors = append(errors, map[string]string{"auth_id": authID, "error": err.Error()})
			continue
		}
		if fileDeleted {
			deleted++
		}
		disabledStore.clear(authID)
	}
	status := http.StatusOK
	if len(errors) > 0 {
		status = http.StatusInternalServerError
	}
	return jsonManagementResponse(status, map[string]any{"ok": len(errors) == 0, "deleted": deleted, "errors": errors, "status": currentDisabledStatus()})
}

type managementSettings struct {
	Plugin            string `json:"plugin"`
	Version           string `json:"version"`
	AuthDir           string `json:"auth_dir"`
	DisabledStatePath string `json:"disabled_state_path"`
	BanStatePath      string `json:"ban_state_path"`
	AutoDelete401     bool   `json:"auto_delete_401"`
	AutoDelete402     bool   `json:"auto_delete_402"`
	AutoDelete403     bool   `json:"auto_delete_403"`
	Deleted401Count   int    `json:"deleted_401_count"`
	Deleted402Count   int    `json:"deleted_402_count"`
	Deleted403Count   int    `json:"deleted_403_count"`
	AutoEnable429     bool   `json:"auto_enable_429"`
	AutoDelete429     bool   `json:"auto_delete_429"`
}

func currentManagementSettings() managementSettings {
	banStore.ensureLoaded()
	disabledStore.ensureLoaded()
	banStore.mu.Lock()
	authDir := banStore.authDirLocked()
	banPath := banStore.statePathLocked()
	autoEnable429 := banStore.autoEnable429
	autoDelete429 := banStore.autoDelete429
	banStore.mu.Unlock()
	disabledStore.mu.Lock()
	if strings.TrimSpace(disabledStore.authDirLocked()) != "" {
		authDir = disabledStore.authDirLocked()
	}
	disabledPath := disabledStore.statePathLocked()
	autoDelete401 := disabledStore.autoDelete401
	autoDelete402 := disabledStore.autoDelete402
	autoDelete403 := disabledStore.autoDelete403
	deleted401 := disabledStore.deleted401
	deleted402 := disabledStore.deleted402
	deleted403 := disabledStore.deleted403
	disabledStore.mu.Unlock()
	return managementSettings{Plugin: pluginName, Version: pluginVersion, AuthDir: authDir, DisabledStatePath: disabledPath, BanStatePath: banPath, AutoDelete401: autoDelete401, AutoDelete402: autoDelete402, AutoDelete403: autoDelete403, Deleted401Count: deleted401, Deleted402Count: deleted402, Deleted403Count: deleted403, AutoEnable429: autoEnable429, AutoDelete429: autoDelete429}
}

func authIndexForFile(authID string) string {
	path, err := banStore.authFilePath(authID)
	if err != nil {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	for _, key := range []string{"auth_index", "authIndex"} {
		if value, ok := body[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func currentBanStatus() managementBanStatus {
	now := time.Now()
	banStore.clearExpired(now)
	snapshot := banStore.snapshot()
	bans := make([]managementBanInfo, 0, len(snapshot))
	for authID, entry := range snapshot {
		remaining := int64(0)
		if now.Before(entry.ResetAt) {
			remaining = int64(entry.ResetAt.Sub(now).Seconds())
		}
		info := managementBanInfo{
			AuthID:           authID,
			Window:           entry.Window,
			ResetAt:          entry.ResetAt.Format(time.RFC3339),
			ResetAtUnix:      entry.ResetAt.Unix(),
			RemainingSeconds: remaining,
			AuthIndex:        authIndexForFile(authID),
		}
		if !entry.BannedAt.IsZero() {
			info.BannedAt = entry.BannedAt.Format(time.RFC3339)
			info.BannedAtUnix = entry.BannedAt.Unix()
		}
		bans = append(bans, info)
	}
	sort.Slice(bans, func(i, j int) bool {
		if bans[i].ResetAtUnix == bans[j].ResetAtUnix {
			return bans[i].AuthID < bans[j].AuthID
		}
		return bans[i].ResetAtUnix < bans[j].ResetAtUnix
	})
	return managementBanStatus{
		Plugin:  pluginName,
		Version: pluginVersion,
		Count:   len(bans),
		Bans:    bans,
	}
}

type managementUnbanRequest struct {
	AuthID string `json:"auth_id"`
	All    bool   `json:"all"`
}

func handleManagementUnban(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body managementUnbanRequest
	if len(req.Body) > 0 {
		if errUnmarshal := json.Unmarshal(req.Body, &body); errUnmarshal != nil {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{
				"error":   "invalid_json",
				"message": errUnmarshal.Error(),
			})
		}
	}
	if strings.EqualFold(req.Query.Get("all"), "true") || body.All {
		return handleManagementUnbanAll()
	}

	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		authID = strings.TrimSpace(req.Query.Get("auth_id"))
	}
	if authID == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{
			"error":   "missing_auth_id",
			"message": "provide auth_id in JSON body or query string",
		})
	}

	entry, removed := banStore.clear(authID)
	if removed {
		slog.Info("codex-429-autoban: manually re-enabled credential",
			"auth_id", authID, "window", entry.Window, "reset_at", entry.ResetAt.Format(time.RFC3339))
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{
		"ok":      true,
		"auth_id": authID,
		"removed": removed,
		"status":  currentBanStatus(),
	})
}

func handleManagementUnbanAll() pluginapi.ManagementResponse {
	removed := banStore.clearAll()
	if removed > 0 {
		slog.Info("codex-429-autoban: manually re-enabled all credentials", "removed", removed)
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{
		"ok":      true,
		"removed": removed,
		"status":  currentBanStatus(),
	})
}

func handleManagementSettings(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body struct {
		AutoDelete401 *bool `json:"auto_delete_401"`
		AutoDelete402 *bool `json:"auto_delete_402"`
		AutoDelete403 *bool `json:"auto_delete_403"`
		AutoEnable429 *bool `json:"auto_enable_429"`
		AutoDelete429 *bool `json:"auto_delete_429"`
	}
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "invalid_json", "message": err.Error()})
		}
	}
	if body.AutoDelete401 == nil && body.AutoDelete402 == nil && body.AutoDelete403 == nil && body.AutoEnable429 == nil && body.AutoDelete429 == nil {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "missing_setting", "message": "provide auto_delete_401, auto_delete_402, auto_delete_403, auto_enable_429 or auto_delete_429 in JSON body"})
	}
	if body.AutoDelete401 != nil {
		disabledStore.setAutoDeleteStatus(statusUnauthorized, *body.AutoDelete401)
	}
	if body.AutoDelete402 != nil {
		disabledStore.setAutoDeleteStatus(statusPaymentRequired, *body.AutoDelete402)
	}
	if body.AutoDelete403 != nil {
		disabledStore.setAutoDeleteStatus(statusForbidden, *body.AutoDelete403)
	}
	if body.AutoEnable429 != nil {
		banStore.setAutoEnable429(*body.AutoEnable429)
	}
	if body.AutoDelete429 != nil {
		banStore.setAutoDelete429(*body.AutoDelete429)
	}
	return jsonManagementResponse(http.StatusOK, currentManagementSettings())
}

func handleManagementDeleteBan(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body managementUnbanRequest
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "invalid_json", "message": err.Error()})
		}
	}
	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		authID = strings.TrimSpace(req.Query.Get("auth_id"))
	}
	if authID == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "missing_auth_id", "message": "provide auth_id in JSON body or query string"})
	}
	deleted, err := banStore.deleteAuthFile(authID)
	if err != nil {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{"error": "delete_failed", "message": err.Error()})
	}
	_, removed := banStore.removeStateOnly(authID)
	if deleted {
		slog.Warn("codex-429-autoban: deleted credential file", "auth_id", authID)
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{"ok": true, "auth_id": authID, "deleted": deleted, "removed": removed, "status": currentBanStatus()})
}

func handleManagementDeleteAllBans() pluginapi.ManagementResponse {
	snapshot := banStore.snapshot()
	deleted := 0
	for authID := range snapshot {
		ok, err := banStore.deleteAuthFile(authID)
		if err != nil {
			slog.Warn("codex-429-autoban: failed to delete auth file", "auth_id", authID, "error", err)
			continue
		}
		if ok {
			deleted++
		}
	}
	removed := banStore.clearAllStateOnly()
	if deleted > 0 {
		slog.Warn("codex-429-autoban: deleted credential files", "deleted", deleted)
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{"ok": true, "deleted": deleted, "removed": removed, "status": currentBanStatus()})
}

func matchesManagementPath(path, suffix string) bool {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if path == "" {
		return false
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return strings.HasSuffix(path, managementRoutePrefix+suffix)
}

func matchesResourcePath(path, suffix string) bool {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if path == "" {
		return false
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return strings.HasSuffix(path, "/v0/resource/plugins/"+pluginName+suffix) ||
		strings.HasSuffix(path, "/plugins/"+pluginName+suffix)
}

func jsonManagementResponse(status int, v any) pluginapi.ManagementResponse {
	raw, errMarshal := json.MarshalIndent(v, "", "  ")
	if errMarshal != nil {
		status = http.StatusInternalServerError
		raw, _ = json.Marshal(map[string]any{
			"error":   "marshal_error",
			"message": errMarshal.Error(),
		})
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type": []string{"application/json; charset=utf-8"},
		},
		Body: raw,
	}
}

func htmlManagementResponse(status int, body string) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Body: []byte(body),
	}
}

func formatRemainingDuration(seconds int64) string {
	minutes := int64(0)
	if seconds > 0 {
		minutes = (seconds + 59) / 60
	}
	days := minutes / (24 * 60)
	minutes %= 24 * 60
	hours := minutes / 60
	minutes %= 60
	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, strconv.FormatInt(days, 10)+" 天")
	}
	if hours > 0 {
		parts = append(parts, strconv.FormatInt(hours, 10)+" 小时")
	}
	if minutes > 0 || len(parts) == 0 {
		parts = append(parts, strconv.FormatInt(minutes, 10)+" 分钟")
	}
	return strings.Join(parts, " ")
}

func formatBeijingUnix(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return formatBeijingTime(time.Unix(unix, 0))
}

func formatBeijingTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(time.FixedZone("CST", 8*60*60)).Format("2006-01-02 15:04:05")
}

func managementStatusPage() string {
	disabledStatus := currentDisabledStatus()
	banStatus := currentBanStatus()
	settings := currentManagementSettings()

	var disabledCards strings.Builder
	if len(disabledStatus.Disabled) == 0 {
		disabledCards.WriteString(`<div class="empty">当前没有被 401/402/403 停用的凭证</div>`)
	} else {
		for _, item := range disabledStatus.Disabled {
			disabledCards.WriteString(`<article class="credential-card" data-auth="` + html.EscapeString(item.AuthID) + `" data-status="` + strconv.Itoa(item.StatusCode) + `" onclick="toggleCardSelection(event, 'disabled')"><label class="check"><input class="disabled-check" type="checkbox" value="` + html.EscapeString(item.AuthID) + `" onchange="updateSelection('disabled')"></label><div class="card-main"><div class="auth-id">` + html.EscapeString(item.AuthID) + `</div><div class="meta">` + html.EscapeString(item.Reason) + ` · HTTP ` + strconv.Itoa(item.StatusCode) + `<br><span class="time-line">` + html.EscapeString(formatBeijingUnix(item.DisabledAtUnix)) + `</span></div></div><div class="card-actions"><button class="secondary" data-auth="` + html.EscapeString(item.AuthID) + `" onclick="enableAuth(this.dataset.auth)">恢复</button><button class="danger" data-auth="` + html.EscapeString(item.AuthID) + `" onclick="deleteDisabled(this.dataset.auth)">删除文件</button></div></article>`)
		}
	}

	var banCards strings.Builder
	if len(banStatus.Bans) == 0 {
		banCards.WriteString(`<div class="empty">当前没有被 429 停用的凭证</div>`)
	} else {
		for _, item := range banStatus.Bans {
			banCards.WriteString(`<article class="credential-card" data-auth="` + html.EscapeString(item.AuthID) + `" data-auth-index="` + html.EscapeString(item.AuthIndex) + `" onclick="toggleCardSelection(event, 'ban')"><label class="check"><input class="ban-check" type="checkbox" value="` + html.EscapeString(item.AuthID) + `" onchange="updateSelection('ban')"></label><div class="card-main"><div class="auth-id">` + html.EscapeString(item.AuthID) + `</div><div class="meta">窗口 ` + html.EscapeString(item.Window) + ` · 剩余 ` + formatRemainingDuration(item.RemainingSeconds) + `<br><span class="reset-line">重置时间：` + html.EscapeString(formatBeijingUnix(item.ResetAtUnix)) + `</span></div></div><div class="card-actions"><button class="secondary" data-auth="` + html.EscapeString(item.AuthID) + `" data-auth-index="` + html.EscapeString(item.AuthIndex) + `" onclick="checkQuota(this)">查询额度</button><button class="secondary" data-auth="` + html.EscapeString(item.AuthID) + `" onclick="unbanAuth(this.dataset.auth)">恢复</button><button class="danger" data-auth="` + html.EscapeString(item.AuthID) + `" onclick="deleteBan(this.dataset.auth)">删除文件</button></div></article>`)
		}
	}

	settingsJSON, _ := json.Marshal(settings)
	autoSwitch := func(id, key, description string, enabled bool, countID string, deletedCount int) string {
		className := "off"
		state := "已关闭"
		if enabled {
			className = "on"
			state = "已开启"
		}
		countHTML := ""
		if countID != "" {
			countHTML = `<span id="` + countID + `" class="delete-count">已删除 ` + strconv.Itoa(deletedCount) + `</span>`
		}
		return `<button id="` + id + `" class="switch-button ` + className + `" role="switch" aria-checked="` + strconv.FormatBool(enabled) + `" onclick="toggleAutoDelete('` + key + `')">` + countHTML + `<span class="switch-label">` + html.EscapeString(description) + `</span><span class="switch-side"><span class="switch-state">` + state + `</span><span class="switch-track"><span class="switch-knob"></span></span></span></button>`
	}
	auto401Switch := autoSwitch("toggleAuto401", "auto_delete_401", "自动删除 401：当请求遇到401凭证时自动删除该凭证。", settings.AutoDelete401, "deletedCount401", settings.Deleted401Count)
	auto402Switch := autoSwitch("toggleAuto402", "auto_delete_402", "自动删除 402：当请求遇到402凭证时自动删除该凭证。", settings.AutoDelete402, "deletedCount402", settings.Deleted402Count)
	auto403Switch := autoSwitch("toggleAuto403", "auto_delete_403", "自动删除 403：当请求遇到403凭证时自动删除该凭证。", settings.AutoDelete403, "deletedCount403", settings.Deleted403Count)
	autoEnable429Switch := autoSwitch("toggleAutoEnable429", "auto_enable_429", "自动启用 429：重置时间到了自动启用该凭证。", settings.AutoEnable429, "", 0)
	auto429Switch := autoSwitch("toggleAuto429", "auto_delete_429", "自动删除 429：当请求遇到429凭证时自动删除该凭证。", settings.AutoDelete429, "", 0)
	return `<!doctype html>
<html lang="zh-Hans">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(pluginName) + `</title>
<script>
(function(){
  var storageKey = 'cli-proxy-theme';
  function storedTheme(){
    try{ var raw = localStorage.getItem(storageKey); if(!raw){ return 'white'; } var parsed = JSON.parse(raw); return (parsed && parsed.state && parsed.state.theme) || parsed.theme || 'white'; }catch(e){ return 'white'; }
  }
  function resolvedTheme(theme){ if(theme === 'dark'){ return 'dark'; } if(theme === 'light'){ return 'light'; } if(theme === 'auto'){ return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'white'; } return 'white'; }
  function applyTheme(){ document.documentElement.setAttribute('data-theme', resolvedTheme(storedTheme())); }
  applyTheme(); window.addEventListener('storage', function(event){ if(event.key === storageKey){ applyTheme(); } });
  if(window.matchMedia){ var mq = window.matchMedia('(prefers-color-scheme: dark)'); if(mq.addEventListener){ mq.addEventListener('change', applyTheme); } }
})();
</script>
<style>
:root,[data-theme=white]{--bg-primary:#fff;--bg-secondary:#f8fafc;--panel:#fff;--text-primary:#0f172a;--text-secondary:#64748b;--border:#e2e8f0;--primary-color:#2563eb;--danger-color:#dc2626;--primary-soft:#2563eb1a;--danger-soft:#dc26261a;--shadow:0 18px 45px rgba(15,23,42,.08)}
[data-theme=light]{--bg-primary:#f0eee8;--bg-secondary:#faf9f5;--panel:#fffaf0;--text-primary:#2f2a24;--text-secondary:#6f675e;--border:#ded7ca;--primary-color:#2563eb;--danger-color:#dc2626;--primary-soft:#2563eb1a;--danger-soft:#dc26261a;--shadow:0 18px 45px rgba(58,45,28,.10)}
[data-theme=dark]{--bg-primary:#0f172a;--bg-secondary:#111827;--panel:#1e293b;--text-primary:#e5e7eb;--text-secondary:#94a3b8;--border:#334155;--primary-color:#60a5fa;--danger-color:#f87171;--primary-soft:#1d4ed833;--danger-soft:#dc262633;--shadow:0 18px 45px rgba(0,0,0,.30)}
*{box-sizing:border-box}body{margin:0;height:100vh;overflow:hidden;background:linear-gradient(180deg,var(--bg-primary),var(--bg-secondary));color:var(--text-primary);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:80%;height:100vh;margin:0 auto;padding:18px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;height:calc(100vh - 36px);min-height:0}.panel{display:flex;flex-direction:column;min-height:0;background:var(--panel);border:1px solid var(--border);border-radius:18px;box-shadow:var(--shadow);padding:18px}.panel-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:12px}.panel-head h2{margin:0}.module-desc{margin:4px 0 0;color:var(--text-secondary);font-size:13px;line-height:1.45}.notice{min-height:20px;color:var(--text-secondary);font-size:13px;text-align:right;white-space:pre-wrap;margin-left:auto}.count{background:var(--primary-soft);color:var(--primary-color);padding:4px 10px;border-radius:999px;font-weight:700}.count-right{align-self:center}.search-row{display:flex;gap:10px}.status-filter{max-width:150px}.search{width:100%;border:1px solid var(--border);border-radius:12px;background:var(--bg-secondary);color:var(--text-primary);padding:10px 12px;margin-bottom:10px;outline:none}.search:focus{border-color:var(--primary-color);box-shadow:0 0 0 3px var(--primary-soft)}.credential-card{cursor:pointer;display:flex;align-items:center;gap:12px;border:1px solid var(--border);border-radius:14px;padding:12px;margin-top:10px;background:color-mix(in srgb,var(--panel) 92%,var(--bg-secondary))}.credential-card[hidden]{display:none}.card-main{min-width:0;flex:1}.auth-id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;overflow-wrap:anywhere}.meta{color:var(--text-secondary);font-size:13px;margin-top:4px;line-height:1.55}.reset-line{display:inline-block;margin-top:2px}.card-actions{display:flex;gap:8px;flex-wrap:wrap}.actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}.bulk-actions{margin-bottom:10px}.right-actions{margin-left:auto;display:flex;gap:10px;align-items:center}.select-all{display:inline-flex;align-items:center;gap:6px;font-weight:700}.selected-count{color:var(--text-secondary);font-size:13px}.list-scroll{flex:1;min-height:0;overflow-y:auto;padding-right:4px}.list-scroll::-webkit-scrollbar{width:8px}.list-scroll::-webkit-scrollbar-thumb{background:var(--border);border-radius:999px}button{border:0;border-radius:10px;padding:8px 12px;font-weight:700;cursor:pointer;background:var(--primary-color);color:#fff}button.secondary{background:var(--primary-soft);color:var(--primary-color)}button.danger{background:var(--danger-color);color:#fff}button.ghost-danger{background:var(--danger-soft);color:var(--danger-color)}button.switch-button{width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;text-align:left;margin:4px 0 12px;background:var(--primary-soft);color:var(--text-primary)}.delete-count{background:var(--bg-secondary);border:1px solid var(--border);border-radius:999px;color:var(--text-secondary);font-size:12px;padding:4px 8px;white-space:nowrap}.switch-side{display:flex;align-items:center;gap:8px;margin-left:auto}.switch-state{color:var(--text-secondary);font-size:13px;white-space:nowrap}.switch-track{width:44px;height:24px;border-radius:999px;background:var(--border);padding:3px;transition:.18s;flex:0 0 auto}.switch-knob{display:block;width:18px;height:18px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(15,23,42,.25);transition:.18s}.switch-button.on .switch-track{background:var(--primary-color)}.switch-button.on .switch-knob{transform:translateX(20px)}.switch-label{font-weight:700}.empty{padding:22px;border:1px dashed var(--border);border-radius:14px;color:var(--text-secondary);text-align:center}@supports (height:100dvh){body,.wrap{height:100dvh}.grid{height:calc(100dvh - 36px)}}@media(max-width:820px){.grid{grid-template-columns:1fr}.wrap{padding:12px}.right-actions{margin-left:0;width:100%;justify-content:flex-end}}
</style>
</head>
<body><main class="wrap">
<section class="grid"><div class="panel"><div class="panel-head"><div><h2>401/402/403 停用列表</h2><p class="module-desc">当在请求CODEX遇到对应状态码的凭证时,会自动停用该凭证,保证不再轮询到该凭证。以减少请求时间。</p></div><div id="msg" class="notice" aria-live="polite"></div></div>` + auto401Switch + auto402Switch + auto403Switch + `<div class="search-row"><select id="disabledStatusFilter" class="search status-filter" onchange="filterList('disabled')"><option value="">全部状态码</option><option value="401">401</option><option value="402">402</option><option value="403">403</option></select><input id="disabledSearch" class="search" type="search" placeholder="搜索账号" oninput="filterList('disabled')"></div><div class="actions bulk-actions"><label class="select-all"><input id="selectAllDisabled" type="checkbox" onchange="toggleAll('disabled', this.checked)"> 全选</label><span class="selected-count">已选 <span id="disabledSelectedCount">0</span></span><button class="secondary" onclick="enableSelected()">恢复所选</button><button class="ghost-danger" onclick="deleteSelectedDisabled()">删除所选</button><span class="right-actions"><button class="secondary" onclick="refreshList('disabled')">刷新</button><span id="disabledCount" class="count count-right">` + strconv.Itoa(disabledStatus.Count) + `</span></span></div><div id="disabledList" class="list-scroll">` + disabledCards.String() + `</div></div>
<div class="panel"><div class="panel-head"><div><h2>429 停用列表</h2><p class="module-desc">当在请求CODEX遇到对应状态码的凭证时,会自动停用该凭证,保证不再轮询到该凭证。以减少请求时间。</p></div></div>` + autoEnable429Switch + auto429Switch + `<input id="banSearch" class="search" type="search" placeholder="搜索账号" oninput="filterList('ban')"><div class="actions bulk-actions"><label class="select-all"><input id="selectAllBan" type="checkbox" onchange="toggleAll('ban', this.checked)"> 全选</label><span class="selected-count">已选 <span id="banSelectedCount">0</span></span><button class="secondary" onclick="unbanSelected()">恢复所选</button><button class="ghost-danger" onclick="deleteSelectedBans()">删除所选</button><span class="right-actions"><button class="secondary" onclick="refreshList('ban')">刷新</button><span id="banCount" class="count count-right">` + strconv.Itoa(banStatus.Count) + `</span></span></div><div id="banList" class="list-scroll">` + banCards.String() + `</div></div></section>
</main>
<script>
const initialSettings = ` + string(settingsJSON) + `;
const base = '/v0/management/plugins/` + pluginName + `';
const msg = document.getElementById('msg');
function show(t){ if(msg){ msg.textContent = t || ''; } }
function listConfig(kind){ return kind === 'disabled' ? {list:'disabledList', count:'disabledCount', search:'disabledSearch', checks:'.disabled-check', master:'selectAllDisabled', selected:'disabledSelectedCount'} : {list:'banList', count:'banCount', search:'banSearch', checks:'.ban-check', master:'selectAllBan', selected:'banSelectedCount'}; }
function decodeStored(raw){
  if(!raw || raw.indexOf('enc::v1::') !== 0){ return raw; }
  try{
    const key = new TextEncoder().encode('cli-proxy-api-webui::secure-storage|' + window.location.host + '|' + navigator.userAgent);
    const bin = atob(raw.slice(9));
    const out = new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++){ out[i] = bin.charCodeAt(i) ^ key[i % key.length]; }
    return new TextDecoder().decode(out);
  }catch(e){ return raw; }
}
function readStoredJSON(key){
  const raw = localStorage.getItem(key);
  if(!raw){ return null; }
  const text = decodeStored(raw);
  try{ return JSON.parse(text); }catch(e){ return text; }
}
function readManagementKey(){
  const direct = readStoredJSON('managementKey');
  if(typeof direct === 'string' && direct){ return direct; }
  const auth = readStoredJSON('cli-proxy-auth');
  return (auth && auth.state && auth.state.managementKey) || (auth && auth.managementKey) || '';
}
function headers(){ const h = {'Content-Type':'application/json'}; const key = readManagementKey(); if(key){ h.Authorization = 'Bearer ' + key; } return h; }
async function postJSON(path, body){ const h = headers(); if(!h.Authorization){ show('未读取到 CPA 管理密钥，请在 CPA 登录页勾选记住密码后重新登录，再打开插件页面。'); return false; } const r = await fetch(base + path, {method:'POST', headers: h, body: JSON.stringify(body||{})}); const text = await r.text(); if(!r.ok){ show('请求失败 HTTP '+r.status+'\n'+text); return false; } return true; }
async function post(path, body, refreshKind){ const ok = await postJSON(path, body); if(!ok){ return; } if(refreshKind){ await refreshList(refreshKind); show('操作完成'); return; } location.reload(); }
async function refreshList(kind){ const cfg = listConfig(kind); show('正在刷新...'); const r = await fetch(window.location.href, {cache:'no-store'}); const text = await r.text(); if(!r.ok){ show('刷新失败 HTTP '+r.status+'\n'+text); return; } const doc = new DOMParser().parseFromString(text, 'text/html'); const nextList = doc.getElementById(cfg.list); const nextCount = doc.getElementById(cfg.count); if(nextList && nextCount){ document.getElementById(cfg.list).innerHTML = nextList.innerHTML; document.getElementById(cfg.count).textContent = nextCount.textContent; filterList(kind); show(''); } }
function visibleChecks(kind){ const cfg = listConfig(kind); return Array.from(document.querySelectorAll(cfg.checks)).filter(e => !e.closest('.credential-card').hidden); }
function toggleCardSelection(event, kind){ if(event.target.closest('button,input,label')){ return; } const card = event.currentTarget; const box = card.querySelector('input[type=checkbox]'); if(!box){ return; } box.checked = !box.checked; updateSelection(kind); }
function updateSelection(kind){ const cfg = listConfig(kind); const checks = Array.from(document.querySelectorAll(cfg.checks)); const checked = checks.filter(e => e.checked); const visible = visibleChecks(kind); const visibleChecked = visible.filter(e => e.checked); const selected = document.getElementById(cfg.selected); const master = document.getElementById(cfg.master); if(selected){ selected.textContent = checked.length; } if(master){ master.checked = visible.length > 0 && visibleChecked.length === visible.length; master.indeterminate = visibleChecked.length > 0 && visibleChecked.length < visible.length; } }
function toggleAll(kind, checked){ visibleChecks(kind).forEach(e => e.checked = checked); updateSelection(kind); }
function filterList(kind){ const cfg = listConfig(kind); const input = document.getElementById(cfg.search); const q = input ? input.value.trim().toLowerCase() : ''; const statusFilter = kind === 'disabled' ? document.getElementById('disabledStatusFilter') : null; const status = statusFilter ? statusFilter.value : ''; document.querySelectorAll('#' + cfg.list + ' .credential-card').forEach(card => { const auth = (card.dataset.auth || '').toLowerCase(); const cardStatus = card.dataset.status || ''; card.hidden = (!!q && auth.indexOf(q) < 0) || (!!status && cardStatus !== status); }); updateSelection(kind); }
function selectedValues(kind){ const cfg = listConfig(kind); return Array.from(document.querySelectorAll(cfg.checks + ':checked')).map(e => e.value); }
async function postSelected(items, path, kind, confirmText){ if(!items.length){ show('请先选择凭证'); return; } if(confirmText && !confirm(confirmText)){ return; } for(const authID of items){ const ok = await postJSON(path, {auth_id:authID}); if(!ok){ return; } } await refreshList(kind); show('已处理 '+items.length+' 个凭证'); }
function toggleAutoDelete(key){ const next = !initialSettings[key]; if(next && key.indexOf('auto_delete_') === 0 && !confirm('开启后,被自动删除的凭证无法恢复,请确认无误后再开启。')){ return; } post('/settings', {[key]: next}); }
function enableAuth(authID){ post('/enable', {auth_id:authID}, 'disabled'); }
function deleteDisabled(authID){ if(confirm('删除 '+authID+' ?')) post('/delete-disabled', {auth_id:authID}, 'disabled'); }
function enableSelected(){ postSelected(selectedValues('disabled'), '/enable', 'disabled', ''); }
function deleteSelectedDisabled(){ const items = selectedValues('disabled'); postSelected(items, '/delete-disabled', 'disabled', '删除所选 '+items.length+' 个 401/402/403 停用凭证文件？'); }
function decodeJWTPart(token){ try{ const part = String(token||'').split('.')[1]; if(!part){ return null; } const padded = part.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(part.length/4)*4,'='); return JSON.parse(atob(padded)); }catch(e){ return null; } }
function accountIDFromAuth(auth){ const tokens = [auth && auth.id_token, auth && auth.idToken, auth && auth.metadata && auth.metadata.id_token, auth && auth.attributes && auth.attributes.id_token]; for(const token of tokens){ const payload = decodeJWTPart(token); const id = payload && (payload.chatgpt_account_id || payload.chatgptAccountId); if(id){ return id; } } return ''; }
async function fetchAuthMeta(authID, h){ const r = await fetch('/v0/management/auth-files', {headers:h, cache:'no-store'}); if(!r.ok){ throw new Error('读取认证列表失败 HTTP '+r.status); } const data = await r.json(); const list = Array.isArray(data) ? data : (Array.isArray(data.files) ? data.files : (Array.isArray(data.auth_files) ? data.auth_files : [])); const auth = list.find(e => (e.name || e.filename || e.auth_id || e.authId) === authID) || {}; let authIndex = auth.auth_index || auth.authIndex || ''; let accountID = accountIDFromAuth(auth); if(!authIndex || !accountID){ const d = await fetch('/v0/management/auth-files/download?name='+encodeURIComponent(authID), {headers:h, cache:'no-store'}); if(d.ok){ try{ const full = JSON.parse(await d.text()); authIndex = authIndex || full.auth_index || full.authIndex || ''; accountID = accountID || accountIDFromAuth(full); }catch(e){} } } return {authIndex:authIndex, accountID:accountID}; }
async function checkQuota(button){
  const authID = button.dataset.auth;
  const h = headers();
  if(!h.Authorization){ show('未读取到 CPA 管理密钥，请在 CPA 登录页勾选记住密码后重新登录，再打开插件页面。'); return; }
  show('正在查询 '+authID+' 额度...');
  let meta; try{ meta = await fetchAuthMeta(authID, h); }catch(e){ show(e.message || String(e)); return; }
  const authIndex = meta.authIndex || button.dataset.authIndex;
  if(!authIndex){ show('查询额度失败：认证文件缺少 auth_index'); return; }
  const quotaHeader = {Authorization:'Bearer $TOKEN$', 'Content-Type':'application/json', 'User-Agent':'codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal'};
  if(meta.accountID){ quotaHeader['Chatgpt-Account-Id'] = meta.accountID; }
  const callQuota = () => fetch('/v0/management/api-call', {method:'POST', headers:h, body:JSON.stringify({authIndex:authIndex, method:'GET', url:'https://chatgpt.com/backend-api/wham/usage', header:quotaHeader})});
  let r = await callQuota();
  let text = await r.text();
  if(r.status === 502 && quotaHeader['Chatgpt-Account-Id']){ console.warn('retrying without Chatgpt-Account-Id'); delete quotaHeader['Chatgpt-Account-Id']; r = await callQuota(); text = await r.text(); }
  if(!r.ok){ show('查询额度失败 HTTP '+r.status+'\n'+text); return; }
  let data; try{ data = JSON.parse(text); }catch(e){ show('查询额度返回无法解析'); return; }
  const status = Number(data.status_code || data.statusCode || 0);
  if(status < 200 || status >= 300){ show('查询额度失败，上游 HTTP '+status); return; }
  const body = data.body || data.bodyText || data;
  if(!quotaAvailable(body)){ show('额度仍不可用，未恢复 '+authID); return; }
  const ok = await postJSON('/unban', {auth_id:authID});
  if(ok){ await refreshList('ban'); show('额度可用，已恢复 '+authID); }
}
function quotaAvailable(body){
  const text = (typeof body === 'string' ? body : JSON.stringify(body || {})).toLowerCase();
  if(text.indexOf('"allowed":true') >= 0){ return true; }
  if(text.indexOf('"limit_reached":false') >= 0 || text.indexOf('"limitreached":false') >= 0){ return true; }
  return false;
}
function unbanAuth(authID){ post('/unban', {auth_id:authID}, 'ban'); }
function deleteBan(authID){ if(confirm('删除 '+authID+' ?')) post('/delete-ban', {auth_id:authID}, 'ban'); }
function unbanSelected(){ postSelected(selectedValues('ban'), '/unban', 'ban', ''); }
function deleteSelectedBans(){ const items = selectedValues('ban'); postSelected(items, '/delete-ban', 'ban', '删除所选 '+items.length+' 个 429 停用凭证文件？'); }
updateSelection('disabled');
updateSelection('ban');
</script>
</body></html>`
}

func headerFloat(h http.Header, key string) float64 {
	raw := h.Get(key)
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	return v
}

func headerInt(h http.Header, key string) int {
	raw := h.Get(key)
	if raw == "" {
		return 0
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return v
}

func headerUnixTime(h http.Header, key string) time.Time {
	raw := h.Get(key)
	if raw == "" {
		return time.Time{}
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}
	}
	if secs <= 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0)
}

// ---- envelope / response helpers ----

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	UsagePlugin   bool `json:"usage_plugin"`
	Scheduler     bool `json:"scheduler"`
	ManagementAPI bool `json:"management_api"`
}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
