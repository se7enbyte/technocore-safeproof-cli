"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  OPERATION_ORDER,
  STATE_VERSION,
  assertNoSecrets,
  canTransition,
  createState,
  nextOperation,
  parseState,
  serializeState,
  transitionOperation,
} = require("../src/state");

const T0 = "2026-08-30T10:00:00.000Z";
const times = Array.from({ length: 16 }, (_, index) =>
  new Date(Date.parse(T0) + index * 1000).toISOString());

function complete(state, name, offset) {
  let next = transitionOperation(state, name, "prepared", { at: times[offset] });
  next = transitionOperation(next, name, "published", {
    at: times[offset + 1],
    receipt: { ok: true, operation: name },
  });
  return transitionOperation(next, name, "verified", {
    at: times[offset + 2],
    receipt: { ok: true, readBack: `/proof/${name}` },
  });
}

test("creates versioned state in required operation order", () => {
  const state = createState({
    at: T0,
    context: { did: "did:key:z6Mktest", fingerprint: "abc123" },
  });
  assert.equal(state.version, STATE_VERSION);
  assert.deepEqual(Object.keys(state.operations), OPERATION_ORDER);
  assert.equal(state.operations.mailbox.enabled, false);
  assert.equal(state.operations.mailbox.status, "pending");
  assert.equal(nextOperation(state), "contribution");
});

test("mailbox is opt-in and follows announcement", () => {
  const state = createState({ at: T0, includeMailbox: true });
  assert.equal(state.operations.mailbox.enabled, true);
  assert.equal(nextOperation(state), "contribution");
});

test("exposes strict status transitions and supports failed retries", () => {
  assert.equal(canTransition("pending", "prepared"), true);
  assert.equal(canTransition("prepared", "published"), true);
  assert.equal(canTransition("prepared", "unknown"), true);
  assert.equal(canTransition("unknown", "published"), true);
  assert.equal(canTransition("published", "verified"), true);
  assert.equal(canTransition("verified", "prepared"), false);
  assert.equal(canTransition("failed", "prepared"), true);

  let state = createState({ at: T0 });
  state = transitionOperation(state, "contribution", "failed", {
    at: times[1],
    error: "network unavailable",
  });
  assert.equal(state.operations.contribution.status, "failed");
  assert.equal(nextOperation(state), "contribution");
  state = transitionOperation(state, "contribution", "prepared", { at: times[2] });
  assert.equal(state.operations.contribution.status, "prepared");
  assert.equal(state.operations.contribution.error, null);
  assert.throws(() => transitionOperation(state, "contribution", "verified", {
    at: times[3], receipt: { ok: true },
  }), /Invalid transition/);
});

test("records immutable status timestamps and receipts", () => {
  const initial = createState({ at: T0 });
  const prepared = transitionOperation(initial, "contribution", "prepared", { at: times[1] });
  const published = transitionOperation(prepared, "contribution", "published", {
    at: times[2],
    receipt: { ok: true, path: "/kv/did-ab/cdef" },
  });
  assert.equal(initial.operations.contribution.status, "pending");
  assert.equal(published.operations.contribution.statusAt, times[2]);
  assert.equal(published.operations.contribution.timestamps.prepared, times[1]);
  assert.equal(published.operations.contribution.timestamps.published, times[2]);
  assert.deepEqual(published.operations.contribution.receipts[0], {
    status: "published",
    at: times[2],
    data: { ok: true, path: "/kv/did-ab/cdef" },
  });
});

test("enforces full operation ordering and resumes at the first unfinished operation", () => {
  let state = createState({ at: T0 });
  state = transitionOperation(state, "profile", "prepared", { at: times[1] });
  assert.throws(() => transitionOperation(state, "profile", "published", {
    at: times[2], receipt: { ok: true },
  }), /Previous operation/);

  state = complete(state, "contribution", 2);
  assert.equal(nextOperation(state), "profile");
  state = transitionOperation(state, "profile", "published", {
    at: times[5], receipt: { ok: true },
  });
  assert.equal(nextOperation(state), "profile");
  state = transitionOperation(state, "profile", "verified", {
    at: times[6], receipt: { ok: true },
  });
  assert.equal(nextOperation(state), "lobby");
});

test("records a timeout as unknown and recovers to published after read-back", () => {
  let state = createState({ at: T0 });
  state = transitionOperation(state, "contribution", "prepared", { at: times[1] });
  state = transitionOperation(state, "contribution", "unknown", {
    at: times[2],
    receipt: { outcome: "timeout", retried: false },
  });
  assert.equal(state.operations.contribution.status, "unknown");
  assert.equal(state.operations.contribution.timestamps.unknown, times[2]);
  assert.equal(nextOperation(state), "contribution");

  state = transitionOperation(state, "contribution", "published", {
    at: times[3],
    receipt: { ok: true, recoveredBy: "read-back", path: "/kv/did-ab/cdef" },
  });
  assert.equal(state.operations.contribution.status, "published");
  assert.equal(state.operations.contribution.receipts.length, 2);
  state = transitionOperation(state, "contribution", "verified", {
    at: times[4],
    receipt: { ok: true, matched: true },
  });
  assert.equal(nextOperation(state), "profile");
});

test("finishes without mailbox and returns null from nextOperation", () => {
  let state = createState({ at: T0 });
  let offset = 1;
  for (const name of OPERATION_ORDER.slice(0, -1)) {
    state = complete(state, name, offset);
    offset += 3;
  }
  assert.equal(nextOperation(state), null);
  assert.throws(() => transitionOperation(state, "mailbox", "prepared", { at: times[15] }), /disabled/);
});

test("safe serialization round-trips a validated state", () => {
  let state = createState({ at: T0, context: { did: "did:key:z6Mktest" } });
  state = transitionOperation(state, "contribution", "prepared", { at: times[1] });
  const serialized = serializeState(state);
  const parsed = parseState(serialized);
  assert.deepEqual(parsed, state);
  parsed.context.did = "changed";
  assert.equal(state.context.did, "did:key:z6Mktest");
});

test("parse validation rejects malformed, unsupported, and inconsistent state", () => {
  assert.throws(() => parseState("{"), /Invalid state JSON/);
  const unsupported = createState({ at: T0 });
  unsupported.version = 999;
  assert.throws(() => parseState(JSON.stringify(unsupported)), /Unsupported state version/);
  const inconsistent = createState({ at: T0 });
  inconsistent.operations.mailbox.enabled = true;
  assert.throws(() => parseState(JSON.stringify(inconsistent)), /Inconsistent enabled flag/);

  const unexpected = createState({ at: T0 });
  unexpected.private = false;
  assert.throws(() => parseState(JSON.stringify(unexpected)), /Unexpected fields/);

  const badTimestamp = createState({ at: T0 });
  badTimestamp.operations.profile.statusAt = times[2];
  assert.throws(() => parseState(JSON.stringify(badTimestamp)), /statusAt exceeds updatedAt/);
});

test("recursive secret guard rejects private key, seed, and Ed25519 d fields", () => {
  for (const unsafe of [
    { privateKey: "secret" },
    { nested: { private_key_jwk: { kty: "OKP" } } },
    { list: [{ seedPhrase: "secret words" }] },
    { publicJwk: { kty: "OKP", crv: "Ed25519", d: "secret" } },
  ]) {
    assert.throws(() => assertNoSecrets(unsafe), /Secret field/);
    assert.throws(() => createState({ at: T0, context: unsafe }), /Secret field/);
  }
});

test("secret guard rejects encoded signature-bearing write URLs at any depth", () => {
  const signed = "https://technocore.chat/r/lobby/say-signed/did%3Akey%3Az6Mk/SECRET/1/message";
  const encoded = encodeURIComponent(signed);
  assert.throws(() => createState({ at: T0, context: { url: signed } }), /Signature-bearing/);
  assert.throws(() => createState({ at: T0, context: { nested: [{ value: encoded }] } }), /Signature-bearing/);
  assert.throws(() => transitionOperation(createState({ at: T0 }), "contribution", "prepared", {
    at: times[1], receipt: { signedWriteUrl: signed },
  }), /Signature-bearing/);
});

test("published and verified transitions require safe receipt objects", () => {
  const state = transitionOperation(createState({ at: T0 }), "contribution", "prepared", { at: times[1] });
  assert.throws(() => transitionOperation(state, "contribution", "published", { at: times[2] }), /requires a receipt/);
  assert.throws(() => transitionOperation(state, "contribution", "published", {
    at: times[2], receipt: "ok",
  }), /requires a receipt/);
  assert.throws(() => transitionOperation(state, "contribution", "published", {
    at: times[2], receipt: { seed: "nope" },
  }), /Secret field/);
});
