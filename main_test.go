package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"codex-auth-guard/cpasdk/pluginapi"
)

type testEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
}

func decodeResult[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var env testEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !env.OK {
		t.Fatalf("envelope not ok: %s", string(raw))
	}
	var result T
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("decode result: %v; raw=%s", err, string(env.Result))
	}
	return result
}

func resetStoresForTest(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()

	banStore.mu.Lock()
	oldBans := banStore.bans
	oldBanPath := banStore.path
	oldBanAuthDir := banStore.authDir
	oldAutoEnable429 := banStore.autoEnable429
	oldAutoDelete429 := banStore.autoDelete429
	oldBanLoaded := banStore.loaded
	banStore.bans = make(map[string]banEntry)
	banStore.path = filepath.Join(tmp, "bans.json")
	banStore.authDir = tmp
	banStore.autoEnable429 = true
	banStore.autoDelete429 = false
	banStore.loaded = true
	banStore.mu.Unlock()

	disabledStore.mu.Lock()
	oldDisabled := disabledStore.disabled
	oldDisabledPath := disabledStore.path
	oldDisabledAuthDir := disabledStore.authDir
	oldAutoDelete401 := disabledStore.autoDelete401
	oldAutoDelete402 := disabledStore.autoDelete402
	oldAutoDelete403 := disabledStore.autoDelete403
	oldDeleted401 := disabledStore.deleted401
	oldDeleted402 := disabledStore.deleted402
	oldDeleted403 := disabledStore.deleted403
	oldDisabledLoaded := disabledStore.loaded
	disabledStore.disabled = make(map[string]disableEntry)
	disabledStore.path = filepath.Join(tmp, "disabled.json")
	disabledStore.authDir = tmp
	disabledStore.autoDelete401 = false
	disabledStore.autoDelete402 = false
	disabledStore.autoDelete403 = false
	disabledStore.deleted401 = 0
	disabledStore.deleted402 = 0
	disabledStore.deleted403 = 0
	disabledStore.loaded = true
	disabledStore.mu.Unlock()

	t.Cleanup(func() {
		banStore.mu.Lock()
		banStore.bans = oldBans
		banStore.path = oldBanPath
		banStore.authDir = oldBanAuthDir
		banStore.autoEnable429 = oldAutoEnable429
		banStore.autoDelete429 = oldAutoDelete429
		banStore.loaded = oldBanLoaded
		banStore.mu.Unlock()

		disabledStore.mu.Lock()
		disabledStore.disabled = oldDisabled
		disabledStore.path = oldDisabledPath
		disabledStore.authDir = oldDisabledAuthDir
		disabledStore.autoDelete401 = oldAutoDelete401
		disabledStore.autoDelete402 = oldAutoDelete402
		disabledStore.autoDelete403 = oldAutoDelete403
		disabledStore.deleted401 = oldDeleted401
		disabledStore.deleted402 = oldDeleted402
		disabledStore.deleted403 = oldDeleted403
		disabledStore.loaded = oldDisabledLoaded
		disabledStore.mu.Unlock()
	})
}

func writeAuthFile(t *testing.T, authID string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(banStore.authDir, authID), []byte(`{"provider":"codex","disabled":false}`), 0600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
}

func readAuthDisabled(t *testing.T, authID string) bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(banStore.authDir, authID))
	if err != nil {
		t.Fatalf("read auth file: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode auth file: %v", err)
	}
	disabled, _ := body["disabled"].(bool)
	return disabled
}

func usageRecord(authID string, statusCode int) []byte {
	record := pluginapi.UsageRecord{Provider: providerCodex, AuthID: authID, Failed: true, Failure: pluginapi.UsageFailure{StatusCode: statusCode}}
	raw, _ := json.Marshal(record)
	return raw
}

func usage429(authID string, resetAt time.Time) []byte {
	record := pluginapi.UsageRecord{
		Provider: providerCodex,
		AuthID:   authID,
		Failed:   true,
		Failure:  pluginapi.UsageFailure{StatusCode: statusTooManyRequests},
		ResponseHeaders: http.Header{
			"x-codex-primary-used-percent":   []string{"100"},
			"x-codex-primary-reset-at":       []string{strconv.FormatInt(resetAt.Unix(), 10)},
			"x-codex-primary-window-minutes": []string{"300"},
		},
	}
	raw, _ := json.Marshal(record)
	return raw
}

func TestCombinedPluginRegistrationExposesBothAutoDeleteFields(t *testing.T) {
	resetStoresForTest(t)
	reg := pluginRegistration()
	fields := map[string]bool{}
	for _, field := range reg.Metadata.ConfigFields {
		fields[field.Name] = true
	}
	for _, name := range []string{"auth_dir", "disabled_state_path", "ban_state_path", "auto_delete_401", "auto_delete_402", "auto_delete_403", "auto_enable_429", "auto_delete_429"} {
		if !fields[name] {
			t.Fatalf("missing config field %s in %+v", name, reg.Metadata.ConfigFields)
		}
	}
}

func TestUsage401402403DisablesAuthAndSchedulerSkipsIt(t *testing.T) {
	for _, statusCode := range []int{401, 402, 403} {
		t.Run(strconv.Itoa(statusCode), func(t *testing.T) {
			resetStoresForTest(t)
			authID := "auth-" + strconv.Itoa(statusCode) + ".json"
			writeAuthFile(t, authID)
			if _, err := handleUsage(usageRecord(authID, statusCode)); err != nil {
				t.Fatalf("handle usage: %v", err)
			}
			entry, ok := disabledStore.lookup(authID)
			if !ok || entry.StatusCode != statusCode {
				t.Fatalf("auth should be disabled with status %d, entry=%+v ok=%v", statusCode, entry, ok)
			}
			if !readAuthDisabled(t, authID) {
				t.Fatalf("auth file should be marked disabled")
			}

			req := pluginapi.SchedulerPickRequest{Candidates: []pluginapi.SchedulerAuthCandidate{
				{ID: authID, Provider: providerCodex, Priority: 100},
				{ID: "ok.json", Provider: providerCodex, Priority: 1},
			}}
			rawReq, _ := json.Marshal(req)
			rawResp, err := handleSchedulerPick(rawReq)
			if err != nil {
				t.Fatalf("scheduler pick: %v", err)
			}
			resp := decodeResult[pluginapi.SchedulerPickResponse](t, rawResp)
			if !resp.Handled || resp.AuthID != "ok.json" {
				t.Fatalf("scheduler should skip disabled auth, got %+v", resp)
			}
		})
	}
}

func TestAutoDelete403DeletesAuthFileInsteadOfDisabling(t *testing.T) {
	resetStoresForTest(t)
	disabledStore.setAutoDeleteStatus(statusForbidden, true)
	writeAuthFile(t, "delete-403.json")
	if _, err := handleUsage(usageRecord("delete-403.json", 403)); err != nil {
		t.Fatalf("handle usage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disabledStore.authDir, "delete-403.json")); !os.IsNotExist(err) {
		t.Fatalf("auth file should be deleted, stat err=%v", err)
	}
	if _, ok := disabledStore.lookup("delete-403.json"); ok {
		t.Fatal("auto-deleted auth should not remain disabled")
	}
}

func TestAutoDelete401402403IncrementsDeletedCountsByStatus(t *testing.T) {
	resetStoresForTest(t)
	for _, statusCode := range []int{401, 402, 403} {
		disabledStore.setAutoDeleteStatus(statusCode, true)
		authID := "delete-" + strconv.Itoa(statusCode) + ".json"
		writeAuthFile(t, authID)
		if _, err := handleUsage(usageRecord(authID, statusCode)); err != nil {
			t.Fatalf("handle usage %d: %v", statusCode, err)
		}
	}

	resp := dispatchManagement(pluginapi.ManagementRequest{Method: "GET", Path: "/v0/management/plugins/codex-auth-guard/settings"})
	body := string(resp.Body)
	for _, want := range []string{`"deleted_401_count": 1`, `"deleted_402_count": 1`, `"deleted_403_count": 1`} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings response missing %s in %s", want, body)
		}
	}
}

func TestUsage429PersistsBanAndDisablesAuthFile(t *testing.T) {
	resetStoresForTest(t)
	writeAuthFile(t, "ban.json")
	if _, err := handleUsage(usage429("ban.json", time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("handle usage: %v", err)
	}
	if _, ok := banStore.lookup("ban.json"); !ok {
		t.Fatal("429 should be stored in ban list")
	}
	if !readAuthDisabled(t, "ban.json") {
		t.Fatal("429 should mark auth file disabled")
	}
}

func TestAutoEnable429SwitchControlsExpiredBanRecovery(t *testing.T) {
	resetStoresForTest(t)
	writeAuthFile(t, "expired-429.json")
	banStore.set("expired-429.json", banEntry{ResetAt: time.Now().Add(-time.Minute), Window: "5h"})
	banStore.setAutoEnable429(false)
	if removed := banStore.clearExpired(time.Now()); removed != 0 {
		t.Fatalf("auto enable off should not clear expired bans, removed=%d", removed)
	}
	if _, ok := banStore.lookup("expired-429.json"); !ok {
		t.Fatal("expired ban should remain when auto enable is off")
	}

	banStore.setAutoEnable429(true)
	if removed := banStore.clearExpired(time.Now()); removed != 1 {
		t.Fatalf("auto enable on should clear expired ban, removed=%d", removed)
	}
	if _, ok := banStore.lookup("expired-429.json"); ok {
		t.Fatal("expired ban should be cleared when auto enable is on")
	}
	if readAuthDisabled(t, "expired-429.json") {
		t.Fatal("auth file should be enabled after expired ban is cleared")
	}
}
func TestAutoDelete429DeletesAuthFileInsteadOfBanning(t *testing.T) {
	resetStoresForTest(t)
	banStore.setAutoDelete429(true)
	writeAuthFile(t, "delete-429.json")
	if _, err := handleUsage(usage429("delete-429.json", time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("handle usage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(banStore.authDir, "delete-429.json")); !os.IsNotExist(err) {
		t.Fatalf("auth file should be deleted, stat err=%v", err)
	}
	if _, ok := banStore.lookup("delete-429.json"); ok {
		t.Fatal("auto-deleted auth should not remain banned")
	}
}

func TestSchedulerKeepsExpired429BannedWhenAutoEnableOff(t *testing.T) {
	resetStoresForTest(t)
	writeAuthFile(t, "expired-scheduler.json")
	banStore.set("expired-scheduler.json", banEntry{ResetAt: time.Now().Add(-time.Minute), Window: "5h"})
	if err := banStore.setAuthFileDisabled("expired-scheduler.json", true); err != nil {
		t.Fatalf("disable auth file: %v", err)
	}
	banStore.setAutoEnable429(false)

	req := pluginapi.SchedulerPickRequest{Candidates: []pluginapi.SchedulerAuthCandidate{
		{ID: "expired-scheduler.json", Provider: providerCodex, Priority: 100},
	}}
	rawReq, _ := json.Marshal(req)
	rawResp, err := handleSchedulerPick(rawReq)
	if err != nil {
		t.Fatalf("scheduler pick: %v", err)
	}
	resp := decodeResult[pluginapi.SchedulerPickResponse](t, rawResp)
	if !resp.Handled || resp.AuthID != "" || resp.DelegateBuiltin != "" {
		t.Fatalf("expired 429 ban must stay blocked when auto enable is off, got %+v", resp)
	}
	if _, ok := banStore.lookup("expired-scheduler.json"); !ok {
		t.Fatal("expired ban should remain when auto enable is off during scheduler pick")
	}
	if !readAuthDisabled(t, "expired-scheduler.json") {
		t.Fatal("auth file should remain disabled when auto enable is off during scheduler pick")
	}
}
func TestSchedulerSkipsDisabledAndBannedAndDoesNotFallbackWhenAllBlocked(t *testing.T) {
	resetStoresForTest(t)
	disabledStore.set("disabled.json", disableEntry{Reason: "401 Unauthorized", StatusCode: 401})
	banStore.set("banned.json", banEntry{ResetAt: time.Now().Add(time.Hour), Window: "5h"})

	req := pluginapi.SchedulerPickRequest{Candidates: []pluginapi.SchedulerAuthCandidate{
		{ID: "disabled.json", Provider: providerCodex, Priority: 100},
		{ID: "banned.json", Provider: providerCodex, Priority: 99},
	}}
	rawReq, _ := json.Marshal(req)
	rawResp, err := handleSchedulerPick(rawReq)
	if err != nil {
		t.Fatalf("scheduler pick: %v", err)
	}
	resp := decodeResult[pluginapi.SchedulerPickResponse](t, rawResp)
	if !resp.Handled || resp.AuthID != "" || resp.DelegateBuiltin != "" {
		t.Fatalf("all blocked must be handled without fallback, got %+v", resp)
	}
}

func TestCombinedStatusPageRendersPanelActionsAndScrollableLists(t *testing.T) {
	resetStoresForTest(t)
	disabledStore.set("disabled-ui.json", disableEntry{Reason: "403 Forbidden", StatusCode: 403, DisabledAt: time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)})
	disabledStore.incrementDeletedCount(statusUnauthorized)
	disabledStore.incrementDeletedCount(statusUnauthorized)
	disabledStore.incrementDeletedCount(statusPaymentRequired)
	banStore.set("banned-ui.json", banEntry{ResetAt: time.Date(2026, 7, 9, 2, 3, 4, 0, time.UTC), Window: "5h"})
	resp := dispatchManagement(pluginapi.ManagementRequest{Method: "GET", Path: "/v0/resource/plugins/codex-auth-guard/status"})
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(resp.Body))
	}
	body := string(resp.Body)
	for _, want := range []string{
		"codex-auth-guard",
		"401/402/403",
		"429 停用列表",
		"当在请求CODEX遇到对应状态码的凭证时,会自动停用该凭证,保证不再轮询到该凭证。以减少请求时间。",
		"disabled-ui.json",
		"banned-ui.json",
		"auto_delete_401",
		"auto_delete_429",
		"id=\"deletedCount401\" class=\"delete-count\">已删除 2</span>",
		"id=\"deletedCount402\" class=\"delete-count\">已删除 1</span>",
		"id=\"deletedCount403\" class=\"delete-count\">已删除 0</span>",
		"自动删除 401：当请求遇到401凭证时自动删除该凭证。",
		"自动删除 402：当请求遇到402凭证时自动删除该凭证。",
		"自动删除 403：当请求遇到403凭证时自动删除该凭证。",
		"自动启用 429：重置时间到了自动启用该凭证。",
		"自动删除 429：当请求遇到429凭证时自动删除该凭证。",
		"class=\"switch-state\">已关闭</span><span class=\"switch-track\"",
		"开启后,被自动删除的凭证无法恢复,请确认无误后再开启。",
		"id=\"toggleAuto401\"",
		"class=\"switch-button",
		"role=\"switch\"",
		"aria-checked=\"false\"",
		"id=\"toggleAutoEnable429\"",
		"id=\"toggleAuto429\"",
		"toggleAutoDelete('auto_delete_401')",
		"toggleAutoDelete('auto_enable_429')",
		"toggleAutoDelete('auto_delete_429')",
		"Authorization",
		"Bearer ",
		"readManagementKey",
		"cli-proxy-auth",
		"id=\"disabledStatusFilter\"",
		"<option value=\"\">全部状态码</option>",
		"<option value=\"401\">401</option>",
		"<option value=\"402\">402</option>",
		"<option value=\"403\">403</option>",
		"id=\"disabledSearch\"",
		"id=\"banSearch\"",
		"placeholder=\"搜索账号\"",
		"id=\"selectAllDisabled\"",
		"id=\"selectAllBan\"",
		"type=\"checkbox\"",
		"已选 <span id=\"disabledSelectedCount\">0</span>",
		"已选 <span id=\"banSelectedCount\">0</span>",
		"恢复所选",
		"删除所选",
		"enableSelected()",
		"deleteSelectedDisabled()",
		"unbanSelected()",
		"deleteSelectedBans()",
		"onclick=\"refreshList('disabled')\"",
		"onclick=\"refreshList('ban')\"",
		"id=\"disabledList\"",
		"id=\"banList\"",
		"id=\"disabledCount\"",
		"id=\"banCount\"",
		"class=\"count count-right\"",
		"刷新",
		"class=\"list-scroll\"",
		"max-width:80%",
		"height:100vh",
		"overflow:hidden",
		"height:calc(100vh - 36px)",
		"min-height:0",
		"flex:1",
		"toggleCardSelection(event, 'disabled')",
		"toggleCardSelection(event, 'ban')",
		"overflow-y:auto",
		"cli-proxy-theme",
		"[data-theme=light]",
		"[data-theme=white]",
		"--primary-color:#2563eb",
		"--danger-color:#dc2626",
		"updateSelection('disabled')",
		"updateSelection('ban')",
		"master.indeterminate",
		"filterList('disabled')",
		"filterList('ban')",
		"function toggleCardSelection",
		"data-auth=\"disabled-ui.json\"",
		"data-status=\"403\"",
		"data-auth=\"banned-ui.json\"",
		"HTTP 403<br><span class=\"time-line\">2026-07-06 09:02:03</span>",
		"剩余 ",
		"天",
		"小时",
		"分钟",
		"重置时间：2026-07-09 10:03:04",
		"class=\"reset-line\"",
		"查询额度",
		"checkQuota(this)",
		"function checkQuota",
		"/v0/management/api-call",
		"wham/usage",
		"payload.chatgpt_account_id || payload.chatgptAccountId",
		"retrying without Chatgpt-Account-Id",
		"delete quotaHeader['Chatgpt-Account-Id']",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("status page missing %q in %s", want, body)
		}
	}
	for _, old := range []string{
		`type="checkbox" data-key="auto_delete_401"`,
		`type="checkbox" data-key="auto_delete_429"`,
		`onclick="refreshPage()"`,
		`function refreshPage()`,
		`onclick="enableAll()"`,
		`onclick="deleteAllDisabled()"`,
		`onclick="unbanAll()"`,
		`onclick="deleteAllBans()"`,
		`onclick="selectAll('disabled')"`,
		`onclick="selectAll('ban')"`,
		`function selectAll`,
		`class="hero"`,
		`class="settings"`,
		`auth_dir:`,
		` 秒`,
		`height:95vh`,
		`height:95dvh`,
		` · 重置 `,
	} {
		if strings.Contains(body, old) {
			t.Fatalf("status page still contains old UI %q in %s", old, body)
		}
	}

	for _, label := range []string{
		"自动删除 401：当请求遇到401凭证时自动删除该凭证。",
		"自动删除 402：当请求遇到402凭证时自动删除该凭证。",
		"自动删除 403：当请求遇到403凭证时自动删除该凭证。",
		"自动删除 429：当请求遇到429凭证时自动删除该凭证。",
	} {
		want := `<span class="switch-label">` + label + `</span><span class="switch-side"><span class="switch-state">已关闭</span><span class="switch-track"`
		if !strings.Contains(body, want) {
			t.Fatalf("%s switch state must render beside track: %s", label, body)
		}
	}
	if !strings.Contains(body, `<span class="switch-label">自动启用 429：重置时间到了自动启用该凭证。</span><span class="switch-side"><span class="switch-state">已开启</span><span class="switch-track"`) {
		t.Fatalf("auto enable 429 switch state must render beside track: %s", body)
	}
	if strings.Contains(body, `自动删除 401：已关闭`) || strings.Contains(body, `自动删除 429：已关闭`) {
		t.Fatalf("switch label must contain description instead of state: %s", body)
	}
	message := strings.Index(body, `id="msg"`)
	disabledTitle := strings.Index(body, `<h2>401/402/403 停用列表</h2>`)
	disabledSearch := strings.Index(body, `id="disabledSearch"`)
	if disabledTitle < 0 || message < 0 || disabledSearch < 0 || disabledTitle > message || message > disabledSearch {
		t.Fatalf("request message must render after first list header and before search: title=%d message=%d search=%d", disabledTitle, message, disabledSearch)
	}

	search := strings.Index(body, `id="disabledSearch"`)
	actions := strings.Index(body, `class="actions bulk-actions"`)
	master := strings.Index(body, `id="selectAllDisabled"`)
	refresh := strings.Index(body, `onclick="refreshList('disabled')"`)
	count := strings.Index(body, `id="disabledCount"`)
	list := strings.Index(body, `id="disabledList"`)
	if search < 0 || actions < 0 || master < 0 || refresh < 0 || count < 0 || list < 0 || search > actions || actions > master || master > refresh || refresh > count || count > list {
		t.Fatalf("search/actions/select-all/refresh/count/list order invalid: search=%d actions=%d master=%d refresh=%d count=%d list=%d", search, actions, master, refresh, count, list)
	}
}

func TestFormatRemainingDuration(t *testing.T) {
	for _, tt := range []struct {
		seconds int64
		want    string
	}{
		{0, "0 分钟"},
		{59, "1 分钟"},
		{3600 + 60, "1 小时 1 分钟"},
		{25*3600 + 2*60, "1 天 1 小时 2 分钟"},
	} {
		if got := formatRemainingDuration(tt.seconds); got != tt.want {
			t.Fatalf("formatRemainingDuration(%d)=%q want %q", tt.seconds, got, tt.want)
		}
	}
}
func TestManagementSettingsPersistAndLoadBothAutoDeleteFlags(t *testing.T) {
	resetStoresForTest(t)
	resp := dispatchManagement(pluginapi.ManagementRequest{Method: "POST", Path: "/v0/management/plugins/codex-auth-guard/settings", Body: []byte(`{"auto_delete_401":true,"auto_delete_402":true,"auto_delete_403":true,"auto_enable_429":false,"auto_delete_429":true}`)})
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(resp.Body))
	}
	if !disabledStore.autoDelete401 || banStore.autoEnable429 || !banStore.autoDelete429 {
		t.Fatalf("settings not applied: 401=%v auto_enable_429=%v auto_delete_429=%v", disabledStore.autoDelete401, banStore.autoEnable429, banStore.autoDelete429)
	}
	resp = dispatchManagement(pluginapi.ManagementRequest{Method: "GET", Path: "/v0/management/plugins/codex-auth-guard/settings"})
	if resp.StatusCode != 200 || !strings.Contains(string(resp.Body), `"auto_delete_401": true`) || !strings.Contains(string(resp.Body), `"auto_delete_402": true`) || !strings.Contains(string(resp.Body), `"auto_delete_403": true`) || !strings.Contains(string(resp.Body), `"auto_enable_429": false`) || !strings.Contains(string(resp.Body), `"auto_delete_429": true`) {
		t.Fatalf("settings response missing flags: status=%d body=%s", resp.StatusCode, string(resp.Body))
	}
}
