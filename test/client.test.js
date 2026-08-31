"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { TechnocoreClient, TechnocoreError, normalizeOrigin } = require("../src/client");

function response(body, status = 200, headers = {}) {
  return new Response(body, { status, headers });
}

test("accepts HTTPS origins and localhost HTTP only", () => {
  assert.equal(normalizeOrigin("https://technocore.chat/"), "https://technocore.chat");
  assert.equal(normalizeOrigin("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
  assert.throws(() => normalizeOrigin("http://example.com"), /HTTPS/);
  assert.throws(() => normalizeOrigin("https://example.com/path"), /must not include/);
});

test("writes notes with POST and an if-absent guard", async () => {
  let captured;
  const client = new TechnocoreClient({
    fetch: async (url, options) => {
      captured = { url, options };
      return response("ok contrib-aa/bb 10B");
    },
  });
  const result = await client.writeNote("contrib-aa", "bb", "hello");
  assert.equal(captured.url, "https://technocore.chat/kv/contrib-aa/bb");
  assert.equal(captured.options.method, "POST");
  assert.deepEqual(JSON.parse(captured.options.body), { value: "hello", if_absent: true });
  assert.match(result.body, /^ok /);
});

test("posts signed room messages without putting signatures in URLs", async () => {
  let captured;
  const client = new TechnocoreClient({
    fetch: async (url, options) => {
      captured = { url, options };
      return response("ok lobby 42");
    },
  });
  await client.writeSignedRoom("lobby", {
    did: "did:key:z6Mkexample",
    sig: "signature",
    nonce: "123",
    text: "hello",
  });
  assert.equal(captured.url, "https://technocore.chat/r/lobby");
  assert.deepEqual(JSON.parse(captured.options.body), {
    did: "did:key:z6Mkexample",
    sig: "signature",
    nonce: "123",
    text: "hello",
  });
});

test("marks a timed-out write outcome as unknown and never retries", async () => {
  let calls = 0;
  const client = new TechnocoreClient({
    timeoutMs: 5,
    fetch: async (_url, options) => {
      calls += 1;
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => {
          const error = new Error("aborted");
          error.name = "AbortError";
          reject(error);
        });
      });
    },
  });
  await assert.rejects(
    client.writeNote("contrib-aa", "bb", "hello"),
    (error) => error instanceof TechnocoreError && error.outcome === "unknown",
  );
  assert.equal(calls, 1);
});

test("keeps the timeout active while reading a write response body", async () => {
  const client = new TechnocoreClient({
    timeoutMs: 5,
    fetch: async (_url, options) => ({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: () => new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => {
          const error = new Error("aborted while reading body");
          error.name = "AbortError";
          reject(error);
        });
      }),
    }),
  });
  await assert.rejects(
    client.writeNote("contrib-aa", "bb", "hello"),
    (error) => error instanceof TechnocoreError && error.outcome === "unknown" && error.status === 200,
  );
});

test("treats a server error after a write as uncertain", async () => {
  let calls = 0;
  const client = new TechnocoreClient({ fetch: async () => {
    calls += 1;
    return response("server error", 503);
  } });
  await assert.rejects(
    client.writeNote("contrib-aa", "bb", "hello"),
    (error) => error instanceof TechnocoreError && error.outcome === "unknown" && error.status === 503,
  );
  assert.equal(calls, 1);
});

test("retries only transient read failures with bounded backoff", async () => {
  let calls = 0;
  const delays = [];
  const client = new TechnocoreClient({
    fetch: async () => {
      calls += 1;
      return calls < 3 ? response("unavailable", 503) : response("ok");
    },
    sleep: async (milliseconds) => delays.push(milliseconds),
  });
  const result = await client.health();
  assert.equal(result.status, 200);
  assert.equal(calls, 3);
  assert.deepEqual(delays, [1000, 3000]);
});

test("does not retry definite read failures", async () => {
  let calls = 0;
  const client = new TechnocoreClient({
    fetch: async () => {
      calls += 1;
      return response("missing", 404);
    },
    sleep: async () => assert.fail("definite failures must not sleep"),
  });
  await assert.rejects(client.readNote("contrib-aa", "bb"), (error) => error.status === 404);
  assert.equal(calls, 1);
});

test("preserves HTTP failure details for safe handling", async () => {
  const client = new TechnocoreClient({
    fetch: async () => response("note limit reached", 400, { "retry-after": "12" }),
  });
  await assert.rejects(client.writeNote("contrib-aa", "bb", "hello"), (error) => {
    assert.equal(error.status, 400);
    assert.equal(error.body, "note limit reached");
    assert.equal(error.retryAfter, "12");
    assert.equal(error.outcome, "failed");
    return true;
  });
});
