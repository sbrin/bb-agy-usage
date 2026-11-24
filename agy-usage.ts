import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const DEFAULT_QUOTA_URL = "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary";
const FALLBACK_QUOTA_URL = "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary";
const REFRESH_URL = "https://oauth2.googleapis.com/token";
const CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
// Google requires a client secret to exchange a refresh token. Never embed one
// from the AGY client in a distributable plugin.
const USER_AGENT = "Antigravity/1.2.11";

const KEYRING_SERVICE = "gemini";
const KEYRING_ACCOUNT = "antigravity";
const WINDOWS_KEYRING_TARGET = `${KEYRING_SERVICE}:${KEYRING_ACCOUNT}`;
const GO_KEYRING_BASE64_PREFIX = "go-keyring-base64:";

export interface StoredToken {
  token?: { access_token?: string; refresh_token?: string; expiry?: string };
  id_token?: string;
  id_token_email?: string;
}

export interface QuotaBucket {
  bucketId?: string;
  displayName?: string;
  window?: string;
  remainingFraction?: number;
  resetTime?: string;
}

export interface QuotaGroup {
  displayName?: string;
  buckets?: QuotaBucket[];
}

export interface QuotaSummary {
  groups?: QuotaGroup[];
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

/**
 * On Windows, agy stores its OAuth token in the Windows Credential Manager
 * (keyring) rather than a plain JSON file.
 */
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

function resolveWindowKind(bucket: QuotaBucket): "five-hour" | "weekly" {
  const windowHint = `${bucket.window ?? ""} ${bucket.bucketId ?? ""} ${bucket.displayName ?? ""}`;
  if (/\b5h\b|five[- ]?hour/iu.test(windowHint)) {
    return "five-hour";
  }
  return "weekly";
}

export function normalizeAgyUsage(summary: QuotaSummary, email: string | null): AgyUsageResult {
  const windows: AgyUsageWindow[] = (summary.groups ?? []).flatMap((group) => {
    const name = group.displayName ?? "";
    const groupSuffix = /gemini/iu.test(name)
      ? " (Gemini)"
      : /claude|gpt/iu.test(name)
        ? " (Claude & GPT)"
        : name
          ? ` (${name})`
          : "";
    return (group.buckets ?? []).map((bucket) => {
      const kind = resolveWindowKind(bucket);
      const prefix = kind === "five-hour" ? "5-hour limit" : "Weekly limit";
      const remaining = Number.isFinite(bucket.remainingFraction) ? bucket.remainingFraction! : 1;
      return {
        kind,
        label: `${prefix}${groupSuffix}`,
        usedPercent: Math.max(0, Math.min(100, Math.round((1 - remaining) * 100))),
        resetsAt: typeof bucket.resetTime === "string" ? bucket.resetTime : null,
      };
    });
  });
  if (windows.length === 0) return error("AGY returned no quota windows.");
  return { supported: true, usage: { status: "ok", accountEmail: email, planLabel: "AGY", windows } };
}

async function requestQuota(
  accessToken: string,
  fetcher: typeof fetch,
  quotaUrl?: string,
): Promise<Response> {
  const url = quotaUrl ?? process.env.AGY_QUOTA_URL ?? process.env.ANTIGRAVITY_QUOTA_URL ?? DEFAULT_QUOTA_URL;
  try {
    const res = await fetcher(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify({ project: "aicode-consumers" }),
    });
    if (res.ok || res.status === 401 || res.status === 403 || url !== DEFAULT_QUOTA_URL) {
      return res;
    }
  } catch (cause) {
    if (url !== DEFAULT_QUOTA_URL) throw cause;
  }

  return fetcher(FALLBACK_QUOTA_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      "User-Agent": USER_AGENT,
    },
    body: JSON.stringify({ project: "aicode-consumers" }),
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

/** Returns true if the stored token's expiry is in the past or within 60 s. */
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

/**
 * Invoke the lightweight `agy models` command with a short timeout so the
 * AGY CLI can refresh its OAuth token transparently. Falls back to common
 * installation paths when the host daemon has a minimal PATH.
 */
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
  quotaUrl?: string;
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

  try {
    let response = await requestQuota(accessToken, fetcher, options.quotaUrl);

    if (response.status === 401) {
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
      response = await requestQuota(refreshedToken, fetcher, options.quotaUrl);
    }

    if (response.status === 401 || response.status === 403) {
      return { supported: true, usage: { status: "expired" } };
    }
    if (!response.ok) return error(`AGY quota request failed (HTTP ${response.status}).`);
    return normalizeAgyUsage(await response.json() as QuotaSummary, accountEmail(stored));
  } catch (cause) {
    return error(cause instanceof Error ? cause.message : String(cause));
  }
}
