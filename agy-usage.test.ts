import assert from "node:assert/strict";
import test from "node:test";
import { normalizeAgyUsage, parseKeyringPayload, readAgyUsage, resolvePlanFromCodeAssist } from "./agy-usage.ts";

test("parseKeyringPayload decodes go-keyring-base64 payload", () => {
  const payload = {
    token: { access_token: "tok-123", expiry: "2099-01-01T00:00:00Z" },
    id_token_email: "user@example.com",
  };
  const encoded = `go-keyring-base64:${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")}`;
  assert.deepEqual(parseKeyringPayload(encoded), payload);
});

test("resolvePlanFromCodeAssist extracts Pro, Ultra, and Free tiers", () => {
  assert.deepEqual(
    resolvePlanFromCodeAssist({
      currentTier: { id: "free-tier", name: "Antigravity" },
      paidTier: { id: "g1-pro-tier", name: "Google AI Pro" },
    }),
    { plan: { id: "pro", multiplier: null }, planLabel: "Pro" },
  );
  assert.deepEqual(
    resolvePlanFromCodeAssist({
      paidTier: { id: "g1-ultra-tier", name: "Google AI Ultra" },
    }),
    { plan: null, planLabel: "Ultra" },
  );
  assert.deepEqual(
    resolvePlanFromCodeAssist({
      currentTier: { id: "free-tier", name: "Antigravity" },
    }),
    { plan: { id: "free", multiplier: null }, planLabel: "Free" },
  );
});

test("normalizeAgyUsage extracts live Gemini 5h quota and ignores 3p Claude/GPT buckets", () => {
  const result = normalizeAgyUsage({
    quota: {
      buckets: [
        { modelId: "claude-opus-5-5-high", remainingFraction: 1, resetTime: "2026-11-24T16:00:00Z" },
        { modelId: "gemini-2.5-pro", remainingFraction: 0.83, resetTime: "2026-11-24T15:11:57Z" },
        { modelId: "gemini-3-flash", remainingFraction: 0.85, resetTime: "2026-11-24T15:11:57Z" },
      ],
    },
    summary: {
      groups: [
        {
          displayName: "Claude and GPT models",
          buckets: [
            { bucketId: "3p-weekly", window: "weekly", remainingFraction: 1, resetTime: "2026-12-01T10:00:00Z" },
          ],
        },
      ],
    },
    codeAssist: {
      paidTier: { id: "g1-pro-tier", name: "Google AI Pro" },
    },
    email: "user@example.com",
  });

  assert.equal(result.supported, true);
  assert.equal(result.usage.status, "ok");
  if (result.usage.status === "ok") {
    assert.equal(result.usage.accountEmail, "user@example.com");
    assert.deepEqual(result.usage.plan, { id: "pro", multiplier: null });
    assert.equal(result.usage.planLabel, "Pro");
    assert.deepEqual(result.usage.windows, [
      {
        kind: "five-hour",
        label: "Five-hour limit",
        usedPercent: 17,
        resetsAt: "2026-11-24T15:11:57Z",
      },
    ]);
  }
});

test("readAgyUsage falls back to keyring and queries loadCodeAssist + retrieveUserQuota", async () => {
  const result = await readAgyUsage({
    tokenPaths: ["/nonexistent/path/one"],
    readKeyring: async () => ({
      token: { access_token: "keyring-token", expiry: "2099-01-01T00:00:00Z" },
      id_token_email: "keyring@example.com",
    }),
    fetcher: async (input) => {
      const url = String(input);
      if (url.includes(":loadCodeAssist")) {
        return new Response(JSON.stringify({
          cloudaicompanionProject: "aicode-consumers",
          paidTier: { id: "g1-pro-tier", name: "Google AI Pro" },
        }), { status: 200 });
      }
      if (url.includes(":retrieveUserQuotaSummary")) {
        return new Response(JSON.stringify({ groups: [] }), { status: 200 });
      }
      return new Response(JSON.stringify({
        buckets: [
          { modelId: "gemini-2.5-pro", remainingFraction: 0.72, resetTime: "2026-11-24T15:00:00Z" },
        ],
      }), { status: 200 });
    },
  });

  assert.equal(result.usage.status, "ok");
  if (result.usage.status === "ok") {
    assert.equal(result.usage.accountEmail, "keyring@example.com");
    assert.equal(result.usage.planLabel, "Pro");
    assert.equal(result.usage.windows[0]?.kind, "five-hour");
    assert.equal(result.usage.windows[0]?.usedPercent, 28);
  }
});
