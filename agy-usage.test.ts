import assert from "node:assert/strict";
import test from "node:test";
import { normalizeAgyUsage, parseKeyringPayload, readAgyUsage } from "./agy-usage.ts";

test("parseKeyringPayload decodes go-keyring-base64 payload", () => {
  const payload = {
    token: { access_token: "tok-123", expiry: "2099-01-01T00:00:00Z" },
    id_token_email: "user@example.com",
  };
  const encoded = `go-keyring-base64:${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")}`;
  assert.deepEqual(parseKeyringPayload(encoded), payload);
});

test("parseKeyringPayload decodes plain JSON payload", () => {
  const payload = { token: { access_token: "tok-456" } };
  assert.deepEqual(parseKeyringPayload(JSON.stringify(payload)), payload);
});

test("normalizeAgyUsage maps 5h and weekly buckets", () => {
  const result = normalizeAgyUsage({
    groups: [
      {
        displayName: "Claude and GPT models",
        buckets: [
          {
            bucketId: "3p-weekly",
            displayName: "Weekly Limit Remaining",
            window: "weekly",
            resetTime: "2026-12-01T10:00:00Z",
            remainingFraction: 0.75,
          },
          {
            bucketId: "3p-5h",
            displayName: "Five Hour Limit Remaining",
            window: "5h",
            resetTime: "2026-11-24T15:00:00Z",
            remainingFraction: 0.4,
          },
        ],
      },
    ],
  }, "user@example.com");

  assert.equal(result.supported, true);
  assert.equal(result.usage.status, "ok");
  if (result.usage.status === "ok") {
    assert.equal(result.usage.accountEmail, "user@example.com");
    assert.equal(result.usage.planLabel, "AGY");
    assert.deepEqual(result.usage.windows, [
      {
        kind: "weekly",
        label: "Weekly limit (Claude & GPT)",
        usedPercent: 25,
        resetsAt: "2026-12-01T10:00:00Z",
      },
      {
        kind: "five-hour",
        label: "5-hour limit (Claude & GPT)",
        usedPercent: 60,
        resetsAt: "2026-11-24T15:00:00Z",
      },
    ]);
  }
});

test("readAgyUsage falls back to keyring when token files are missing", async () => {
  const result = await readAgyUsage({
    tokenPaths: ["/nonexistent/path/one", "/nonexistent/path/two"],
    readKeyring: async () => ({
      token: { access_token: "keyring-token", expiry: "2099-01-01T00:00:00Z" },
      id_token_email: "keyring@example.com",
    }),
    fetcher: async () => new Response(JSON.stringify({
      groups: [
        {
          displayName: "Gemini models",
          buckets: [{ window: "weekly", remainingFraction: 0.9, resetTime: "2026-12-01T00:00:00Z" }],
        },
      ],
    }), { status: 200 }),
  });

  assert.equal(result.usage.status, "ok");
  if (result.usage.status === "ok") {
    assert.equal(result.usage.accountEmail, "keyring@example.com");
    assert.equal(result.usage.windows[0]?.usedPercent, 10);
  }
});
