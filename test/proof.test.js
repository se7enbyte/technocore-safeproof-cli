"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { generateIdentity } = require("../src/identity");
const { prepareKit } = require("../src/kit");
const { createPublicProof, serializePublicProof } = require("../src/proof");
const { OPERATION_ORDER, transitionOperation } = require("../src/state");

function stateFixture(identity) {
  return prepareKit(identity, {
    agentName: "safeproof_agent",
    contributionType: "tool",
    contributionSummary: "A safe Technocore publisher.",
    guideUrl: "https://example.com/repo",
  }, { nonceBase: 1700000000000, now: "2026-08-30T12:00:00.000Z" });
}

test("exports a prepared proof without private key material or write URLs", () => {
  const identity = generateIdentity();
  const state = stateFixture(identity);
  const output = serializePublicProof(state);
  assert.equal(output.proof.status, "prepared");
  assert.equal(output.json.includes(identity.privateKeyJwk.d), false);
  assert.equal(output.json.includes("say-signed"), false);
  assert.match(output.markdown, /does not guarantee FLOP rewards/);
  assert.match(output.markdown, /Publication plan only/);
  assert.doesNotMatch(output.markdown, /demonstrates control/);
  assert.equal(output.proof.records.contribution.sha256.length, 64);
});

test("labels non-final operation states as partial", () => {
  const identity = generateIdentity();
  const state = stateFixture(identity);
  state.operations.profile.status = "failed";
  state.operations.profile.statusAt = state.updatedAt;
  state.operations.profile.timestamps.failed = state.updatedAt;
  state.operations.profile.error = "test failure";
  const proof = createPublicProof(state);
  assert.equal(proof.status, "partial");
});

test("requires a fresh successful audit before labeling proof verified", () => {
  const identity = generateIdentity();
  let state = stateFixture(identity);
  let tick = Date.parse(state.updatedAt);
  for (const name of OPERATION_ORDER) {
    if (!state.operations[name].enabled) continue;
    tick += 1;
    state = transitionOperation(state, name, "published", {
      at: new Date(tick).toISOString(),
      receipt: { httpStatus: 200 },
    });
    tick += 1;
    state = transitionOperation(state, name, "verified", {
      at: new Date(tick).toISOString(),
      receipt: name === "contribution" || name === "profile"
        ? { sha256: state.context.records[name].digest }
        : { room: state.context.messages[name].room, seq: tick, ts: new Date(tick).toISOString(), nonce: state.context.messages[name].nonce, sig: "x" },
    });
  }
  assert.equal(createPublicProof(state).status, "partial");
  const checkedAt = "2026-08-30T12:01:00.000Z";
  const output = serializePublicProof(state, { audit: { ok: true, checkedAt, results: {} } });
  assert.equal(output.proof.status, "verified");
  assert.equal(output.proof.liveAudit.checkedAt, checkedAt);
  assert.match(output.markdown, /Live read-back audit passed/);
});
