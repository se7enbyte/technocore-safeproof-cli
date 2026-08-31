"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { generateIdentity } = require("../src/identity");
const { assertPlanContext, prepareKit } = require("../src/kit");
const { assertNoSecrets, nextOperation } = require("../src/state");

const INPUT = {
  agentName: "safeproof_agent",
  contributionType: "tool",
  contributionSummary: "A capacity-aware Technocore publishing CLI.",
  guideUrl: "https://github.com/example/technocore-safeproof-cli",
  xHandle: "safeproof",
};

test("prepares a safe, sharded, contribution-first operation plan", () => {
  const identity = generateIdentity();
  const state = prepareKit(identity, INPUT, {
    nonceBase: 1700000000000,
    now: "2026-08-30T12:00:00.000Z",
  });
  assert.equal(nextOperation(state), "contribution");
  assert.equal(state.context.records.profile.ns, `did-${identity.fingerprint.slice(0, 2)}`);
  assert.equal(state.context.records.contribution.ns, `contrib-${identity.fingerprint.slice(0, 2)}`);
  assert.equal(state.context.messages.lobby.nonce, "1700000000000");
  assert.equal(state.context.messages.announcement.nonce, "1700000000001");
  assert.ok(state.context.messages.announcement.text.includes(state.context.records.contribution.digest));
  assert.ok(state.context.messages.lobby.text.includes(state.context.records.profile.digest));
  assert.equal(state.operations.mailbox.enabled, false);
  assert.equal(JSON.stringify(state).includes(identity.privateKeyJwk.d), false);
  assert.equal(assertNoSecrets(state), true);
  assert.equal(assertPlanContext(state), state);
  assert.match(state.context.authorization.sha256, /^[a-f0-9]{64}$/);
});

test("mailbox is opt-in and generated with cryptographic randomness", () => {
  const identity = generateIdentity();
  const state = prepareKit(identity, { ...INPUT, includeMailbox: true }, {
    nonceBase: 1700000000000,
    now: "2026-08-30T12:00:00.000Z",
    randomBytes: () => Buffer.alloc(12, 0xab),
  });
  assert.equal(state.context.contribution.mailbox, `mb-p-${"ab".repeat(12)}`);
  assert.equal(state.context.messages.mailbox.room, state.context.contribution.mailbox);
  assert.equal(state.operations.mailbox.enabled, true);
});

test("rejects invalid input before creating a publishable plan", () => {
  const identity = generateIdentity();
  assert.throws(() => prepareKit(identity, { ...INPUT, agentName: "../bad" }), /Agent name/);
  assert.throws(() => prepareKit(identity, { ...INPUT, contributionSummary: "\u200b" }), /empty/);
  assert.throws(() => prepareKit(identity, INPUT, { nonceBase: Number.MAX_SAFE_INTEGER }), /leave room/);
});

test("rejects modified or reassembled signed plan contexts", () => {
  const identity = generateIdentity();
  const original = prepareKit(identity, INPUT, {
    nonceBase: 1700000000000,
    now: "2026-08-30T12:00:00.000Z",
  });
  const modified = prepareKit(identity, { ...INPUT, contributionSummary: "Changed statement." }, {
    nonceBase: 1700000000000,
    now: "2026-08-30T12:00:00.000Z",
  });
  modified.context.authorization = original.context.authorization;
  assert.throws(() => assertPlanContext(modified), /digest|signature/i);

  const canonicalTamper = JSON.parse(JSON.stringify(original));
  canonicalTamper.context.messages.lobby.canonical = "lobby|1|sign something else";
  assert.throws(() => assertPlanContext(canonicalTamper), /modified|inconsistent/i);
});
