import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const DEFAULT_API_BASE = "https://daily-cloudcode-pa.googleapis.com";
const FALLBACK_API_BASE = "https://cloudcode-pa.googleapis.com";
const DEFAULT_PROJECT = "aicode-consumers";
const REFRESH_URL = "https://oauth2.googleapis.com/token";
const CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
// Google requires a client secret to exchange a refresh token. Never embed one
// from the AGY client in a distributable plugin.
const USER_AGENT = "Antigravity/1.5.15";

const KEYRING_SERVICE = "gemini";
const KEYRING_ACCOUNT = "antigravity";
const WINDOWS_KEYRING_TARGET = `${KEYRING_SERVICE}:${KEYRING_ACCOUNT}`;
const GO_KEYRING_BASE64_PREFIX = "go-keyring-base64:";

export interface StoredToken {
  token?: { access_token?: string; refresh_token?: string; expiry?: string };
  id_token?: string;
  id_token_email?: string;
}

export interface TierInfo {
  id?: string;
  name?: string;
}

export interface LoadCodeAssistResponse {
  currentTier?: TierInfo;
  paidTier?: TierInfo;
  cloudaicompanionProject?: string | { id?: string };
}

export interface ModelQuotaBucket {
  modelId?: string;
  remainingFraction?: number;
  resetTime?: string;
  tokenType?: string;
}

export interface UserQuotaResponse {
  buckets?: ModelQuotaBucket[];
}

export interface QuotaSummaryBucket {
  bucketId?: string;
  displayName?: string;
  window?: string;
  remainingFraction?: number;
  resetTime?: string;
}

export interface QuotaSummaryGroup {
  displayName?: string;
  buckets?: QuotaSummaryBucket[];
}

export interface QuotaSummaryResponse {
  groups?: QuotaSummaryGroup[];
}

export interface AgyUsagePlan {
  id: string;
  multiplier: number | null;
}

export interface AgyUsageWindow {
  kind: "five-hour" | "weekly";
  label: string;
  usedPercent: number;
  resetsAt: string | null;
}

export type AgyUsageState =
  | {
    status: "ok";
    plan: AgyUsagePlan | null;
    accountEmail: string | null;
    planLabel: string | null;
    windows: AgyUsageWindow[];
  }
  | { status: "not_installed" }
  | { status: "unauthenticated" }
  | { status: "expired" }
  | {
    status: "error";
    message: string;
    accountEmail: string | null;
    planLabel: string | null;
  };

export interface AgyUsageResult {
  supported: boolean;
  usage: AgyUsageState;
}

function error(message: string): AgyUsageResult {
  return { supported: true, usage: { status: "error", message, accountEmail: null, planLabel: null } };
}

/**
 * Decode a raw keyring value written by zalando/go-keyring (used by agy CLI).
 * Values may be stored either as plain UTF-8 JSON or prefixed with
 * `go-keyring-base64:` followed by base64-encoded UTF-8 JSON.
 */
export function parseKeyringPayload(raw: string): StoredToken | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const jsonText = trimmed.startsWith(GO_KEYRING_BASE64_PREFIX)
      ? Buffer.from(trimmed.slice(GO_KEYRING_BASE64_PREFIX.length), "base64").toString("utf8")
      : trimmed;
    const parsed = JSON.parse(jsonText) as unknown;
    return parsed && typeof parsed === "object" ? parsed as StoredToken : null;
  } catch {
    return null;
  }
}

async function readStoredTokenFromMacosKeychain(): Promise<StoredToken | null> {
  if (process.platform !== "darwin") return null;
  try {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const execFileAsync = promisify(execFile);
    const { stdout } = await execFileAsync(
      "security",
      ["find-generic-password", "-s", KEYRING_SERVICE, "-a", KEYRING_ACCOUNT, "-w"],
      { timeout: 5_000, encoding: "utf8" },
    );
    return parseKeyringPayload(stdout);
  } catch {
    return null;
  }
}

async function readStoredTokenFromWindowsKeyring(): Promise<StoredToken | null> {
  if (process.platform !== "win32") return null;
  try {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const execFileAsync = promisify(execFile);
    const script = `
Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;using System.Text;
public static class CredReader {
  [DllImport("Advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern bool CredReadW(string t,uint type,uint flags,out IntPtr p);
  [DllImport("Advapi32.dll")] static extern void CredFree(IntPtr p);
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
  struct CRED{public uint F,T;public string TN,C;public ulong LW;public uint BS;public IntPtr B;public uint P,AC;public IntPtr A;public string TA,U;}
  public static string Read(string target){
    IntPtr p;if(!CredReadW(target,1,0,out p))return null;
    try{var c=Marshal.PtrToStructure<CRED>(p);if(c.BS==0)return "";var b=new byte[c.BS];Marshal.Copy(c.B,b,0,(int)c.BS);return Encoding.UTF8.GetString(b);}
    finally{CredFree(p);}
  }
}
"@ -ErrorAction Stop
$v=[CredReader]::Read("${WINDOWS_KEYRING_TARGET}");if($v){Write-Output $v}else{exit 1}
`.trim();
    const { stdout } = await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { timeout: 8_000, encoding: "utf8", windowsHide: true },
    );
    return parseKeyringPayload(stdout);
  } catch {
    return null;
  }
}

async function readStoredTokenFromLinuxKeyring(): Promise<StoredToken | null> {
  if (process.platform !== "linux") return null;
  try {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const execFileAsync = promisify(execFile);
    const { stdout } = await execFileAsync(
      "secret-tool",
      ["lookup", "service", KEYRING_SERVICE, "username", KEYRING_ACCOUNT],
      { timeout: 5_000, encoding: "utf8" },
    );
    return parseKeyringPayload(stdout);
  } catch {
    return null;
  }
}

async function readStoredTokenFromKeyring(): Promise<StoredToken | null> {
  if (process.platform === "darwin") return readStoredTokenFromMacosKeychain();
  if (process.platform === "win32") return readStoredTokenFromWindowsKeyring();
  if (process.platform === "linux") return readStoredTokenFromLinuxKeyring();
  return null;
}

function defaultTokenPaths(): string[] {
  const home = homedir();
  const candidates = [
    process.env.AGY_TOKEN_PATH,
    process.env.ANTIGRAVITY_TOKEN_PATH,
    join(home, ".gemini", "antigravity-cli", "antigravity-oauth-token"),
    join(home, ".gemini", "antigravity", "antigravity-oauth-token"),
  ].filter((value): value is string => typeof value === "string" && value.trim().length > 0);
  return [...new Set(candidates)];
}

async function readStoredTokenFromFile(filePath: string): Promise<StoredToken | null> {
  try {
    const raw = await readFile(filePath, "utf8");
    return parseKeyringPayload(raw);
  } catch (cause) {
    const code = cause && typeof cause === "object" && "code" in cause ? cause.code : null;
    if (code === "ENOENT") return null;
    throw cause;
  }
}

function accountEmail(stored: StoredToken): string | null {
  if (typeof stored.id_token_email === "string" && stored.id_token_email.trim().length > 0) {
    return stored.id_token_email.trim();
  }
  const idToken = stored.id_token;
  if (!idToken) return null;
  try {
    const payload = idToken.split(".")[1];
    if (!payload) return null;
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { email?: unknown };
    return typeof claims.email === "string" ? claims.email : null;
  } catch {
    return null;
  }
}

export function resolvePlanFromCodeAssist(
  lca: LoadCodeAssistResponse | null,
): { plan: AgyUsagePlan | null; planLabel: string | null } {
  const tier = lca?.paidTier ?? lca?.currentTier;
  if (!tier) return { plan: null, planLabel: null };
  const hint = `${tier.id ?? ""} ${tier.name ?? ""}`;
  if (/\bultra\b/iu.test(hint)) {
    return { plan: null, planLabel: "Ultra" };
  }
  if (/\bpro\b/iu.test(hint)) {
    return { plan: { id: "pro", multiplier: null }, planLabel: "Pro" };
  }
  if (/\benterprise\b/iu.test(hint)) {
    return { plan: { id: "enterprise", multiplier: null }, planLabel: "Enterprise" };
  }
  if (/\bstandard\b|\bteam\b/iu.test(hint)) {
    return { plan: { id: "team", multiplier: null }, planLabel: "Team" };
  }
  if (/\bfree\b/iu.test(hint)) {
    return { plan: { id: "free", multiplier: null }, planLabel: "Free" };
  }
  return { plan: null, planLabel: tier.name?.trim() || null };
}

function resolveProjectId(lca: LoadCodeAssistResponse | null): string {
  const proj = lca?.cloudaicompanionProject;
  if (typeof proj === "string" && proj.trim().length > 0) return proj.trim();
  if (proj && typeof proj === "object" && typeof proj.id === "string" && proj.id.trim().length > 0) {
    return proj.id.trim();
  }
  return DEFAULT_PROJECT;
}

function clampUsedPercent(remainingFraction: number | undefined): number {
  const remaining = Number.isFinite(remainingFraction) ? remainingFraction! : 1;
  return Math.max(0, Math.min(100, Math.round((1 - remaining) * 100)));
}

function resolveSummaryBucketKind(bucket: QuotaSummaryBucket): "five-hour" | "weekly" {
  const hint = `${bucket.window ?? ""} ${bucket.bucketId ?? ""} ${bucket.displayName ?? ""}`;
  if (/\b5h\b|five[- ]?hour/iu.test(hint)) return "five-hour";
  return "weekly";
}

export function normalizeAgyUsage(params: {
  quota: UserQuotaResponse | null;
  summary: QuotaSummaryResponse | null;
  codeAssist: LoadCodeAssistResponse | null;
  email: string | null;
}): AgyUsageResult {
  const { plan, planLabel } = resolvePlanFromCodeAssist(params.codeAssist);
  let fiveHourWindow: AgyUsageWindow | null = null;
  let weeklyWindow: AgyUsageWindow | null = null;

  // 1. Live per-model Gemini quota from retrieveUserQuota (the primary 5-hour rolling window).
  const geminiBuckets = (params.quota?.buckets ?? []).filter(
    (bucket) => typeof bucket.modelId === "string" && /^gemini-/iu.test(bucket.modelId),
  );
  if (geminiBuckets.length > 0) {
    let minRemaining = 1;
    let earliestReset: string | null = null;
    for (const bucket of geminiBuckets) {
      if (Number.isFinite(bucket.remainingFraction) && bucket.remainingFraction! < minRemaining) {
        minRemaining = bucket.remainingFraction!;
      }
      if (typeof bucket.resetTime === "string" && bucket.resetTime.length > 0) {
        if (!earliestReset || bucket.resetTime < earliestReset) {
          earliestReset = bucket.resetTime;
        }
      }
    }
    fiveHourWindow = {
      kind: "five-hour",
      label: "Five-hour limit",
      usedPercent: clampUsedPercent(minRemaining),
      resetsAt: earliestReset,
    };
  }

  // 2. Check retrieveUserQuotaSummary for any Gemini-specific windows (e.g. weekly limit).
  const geminiSummaryGroups = (params.summary?.groups ?? []).filter(
    (group) => /gemini/iu.test(group.displayName ?? ""),
  );
  for (const group of geminiSummaryGroups) {
    for (const bucket of group.buckets ?? []) {
      const kind = resolveSummaryBucketKind(bucket);
      const win: AgyUsageWindow = {
        kind,
        label: kind === "five-hour" ? "Five-hour limit" : "Weekly limit",
        usedPercent: clampUsedPercent(bucket.remainingFraction),
        resetsAt: typeof bucket.resetTime === "string" ? bucket.resetTime : null,
      };
      if (kind === "five-hour" && !fiveHourWindow) {
        fiveHourWindow = win;
      } else if (kind === "weekly" && !weeklyWindow) {
        weeklyWindow = win;
      }
    }
  }

  const windows: AgyUsageWindow[] = [];
  if (fiveHourWindow) windows.push(fiveHourWindow);
  if (weeklyWindow) windows.push(weeklyWindow);

  if (windows.length === 0) {
    return error("AGY returned no Gemini quota windows.");
  }

  return {
    supported: true,
    usage: {
      status: "ok",
      plan,
      accountEmail: params.email,
      planLabel,
      windows,
    },
  };
}

async function callCloudCodeApi(
  endpoint: string,
  body: Record<string, unknown>,
  accessToken: string,
  fetcher: typeof fetch,
  apiBase?: string,
): Promise<Response> {
  const base = apiBase ?? process.env.AGY_API_BASE ?? DEFAULT_API_BASE;
  const primaryUrl = `${base}/v1internal:${endpoint}`;
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
    "User-Agent": USER_AGENT,
  };
  const payload = JSON.stringify(body);
  try {
    const res = await fetcher(primaryUrl, { method: "POST", headers, body: payload });
    if (res.ok || res.status === 401 || res.status === 403 || base !== DEFAULT_API_BASE) {
      return res;
    }
  } catch (cause) {
    if (base !== DEFAULT_API_BASE) throw cause;
  }

  return fetcher(`${FALLBACK_API_BASE}/v1internal:${endpoint}`, {
    method: "POST",
    headers,
    body: payload,
  });
}

async function refreshedAccessToken(refreshToken: string, fetcher: typeof fetch): Promise<string | null> {
  const clientSecret = process.env.AGY_OAUTH_CLIENT_SECRET ?? process.env.ANTIGRAVITY_OAUTH_CLIENT_SECRET;
  if (!clientSecret) return null;
  const response = await fetcher(REFRESH_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: clientSecret,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });
  if (!response.ok) return null;
  const body = await response.json() as { access_token?: unknown };
  return typeof body.access_token === "string" ? body.access_token : null;
}

function isTokenExpired(stored: StoredToken): boolean {
  const expiry = stored.token?.expiry;
  if (!expiry) return false;
  try {
    const normalized = expiry.replace(/(\.\d{3})\d+/, "$1");
    const expiryMs = Date.parse(normalized);
    if (!Number.isFinite(expiryMs)) return false;
    return expiryMs - Date.now() < 60_000;
  } catch {
    return false;
  }
}

async function refreshViaAgyCli(agyCli?: string): Promise<void> {
  if (!agyCli) return;
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const execFileAsync = promisify(execFile);
  const home = homedir();
  const candidates = agyCli.includes("/") || agyCli.includes("\\")
    ? [agyCli]
    : [
      agyCli,
      join(home, ".local", "bin", agyCli),
      `/opt/homebrew/bin/${agyCli}`,
      `/usr/local/bin/${agyCli}`,
    ];

  for (const bin of candidates) {
    try {
      await execFileAsync(bin, ["models"], {
        timeout: 10_000,
        encoding: "utf8",
        windowsHide: true,
        env: { ...process.env, NO_COLOR: "1" },
      });
      return;
    } catch (cause) {
      const code = cause && typeof cause === "object" && "code" in cause ? cause.code : null;
      if (code === "ENOENT") continue;
      return;
    }
  }
}

export async function readAgyUsage(options: {
  tokenPath?: string;
  tokenPaths?: string[];
  readKeyring?: () => Promise<StoredToken | null>;
  fetcher?: typeof fetch;
  agyCli?: string;
  apiBase?: string;
} = {}): Promise<AgyUsageResult> {
  const paths = options.tokenPaths
    ?? (options.tokenPath ? [options.tokenPath] : defaultTokenPaths());
  const readKeyring = options.readKeyring ?? readStoredTokenFromKeyring;
  const fetcher = options.fetcher ?? fetch;

  async function readToken(): Promise<StoredToken | null> {
    let lastError: unknown = null;
    for (const filePath of paths) {
      try {
        const fromFile = await readStoredTokenFromFile(filePath);
        if (fromFile?.token?.access_token) return fromFile;
      } catch (cause) {
        lastError = cause;
      }
    }

    const fromKeyring = await readKeyring();
    if (fromKeyring?.token?.access_token) return fromKeyring;

    if (lastError) throw lastError;
    return null;
  }

  let stored: StoredToken | null;
  try {
    stored = await readToken();
  } catch {
    return error("Could not read the AGY authentication token.");
  }

  if (!stored) return { supported: true, usage: { status: "unauthenticated" } };

  let accessToken = stored.token?.access_token;
  if (!accessToken) return { supported: true, usage: { status: "unauthenticated" } };

  if (isTokenExpired(stored)) {
    await refreshViaAgyCli(options.agyCli);
    try {
      const refreshed = await readToken();
      if (refreshed?.token?.access_token) {
        stored = refreshed;
        accessToken = refreshed.token.access_token;
      }
    } catch { /* ignore, proceed with existing token */ }
  }

  async function fetchAll(token: string) {
    const lcaRes = await callCloudCodeApi(
      "loadCodeAssist",
      { metadata: { ideType: "ANTIGRAVITY" } },
      token,
      fetcher,
      options.apiBase,
    );
    if (lcaRes.status === 401 || lcaRes.status === 403) {
      return { authError: lcaRes.status as 401 | 403 };
    }
    const codeAssist = lcaRes.ok ? (await lcaRes.json() as LoadCodeAssistResponse) : null;
    const project = resolveProjectId(codeAssist);

    const [quotaRes, summaryRes] = await Promise.all([
      callCloudCodeApi("retrieveUserQuota", { project }, token, fetcher, options.apiBase),
      callCloudCodeApi("retrieveUserQuotaSummary", { project }, token, fetcher, options.apiBase)
        .catch(() => null),
    ]);

    if (quotaRes.status === 401 || quotaRes.status === 403) {
      return { authError: quotaRes.status as 401 | 403 };
    }
    if (!quotaRes.ok) {
      return { httpError: quotaRes.status };
    }

    const quota = await quotaRes.json() as UserQuotaResponse;
    const summary = summaryRes?.ok ? (await summaryRes.json() as QuotaSummaryResponse) : null;
    return { codeAssist, quota, summary };
  }

  try {
    let data = await fetchAll(accessToken);

    if ("authError" in data && data.authError === 401) {
      let refreshedToken: string | null = null;
      if (stored.token?.refresh_token) {
        refreshedToken = await refreshedAccessToken(stored.token.refresh_token, fetcher);
      }
      if (!refreshedToken) {
        await refreshViaAgyCli(options.agyCli);
        try {
          const reread = await readToken();
          refreshedToken = reread?.token?.access_token ?? null;
        } catch { /* ignore */ }
      }
      if (!refreshedToken) return { supported: true, usage: { status: "expired" } };
      data = await fetchAll(refreshedToken);
    }

    if ("authError" in data) {
      return { supported: true, usage: { status: "expired" } };
    }
    if ("httpError" in data) {
      return error(`AGY quota request failed (HTTP ${data.httpError}).`);
    }

    return normalizeAgyUsage({
      quota: data.quota,
      summary: data.summary,
      codeAssist: data.codeAssist,
      email: accountEmail(stored),
    });
  } catch (cause) {
    return error(cause instanceof Error ? cause.message : String(cause));
  }
}
