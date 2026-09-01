"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { generateIdentity, sign } = require("../src/identity");
const { prepareKit } = require("../src/kit");
const { auditState } = require("../src/verifier");
const { OPERATION_ORDER, transitionOperation } = require("../src/state");

test("audits records and signed room receipts without loading a private key", async () => {
  const identity = generateIdentity();
  const state = prepareKit(identity, {
    agentName: "safeproof_agent",
    contributionType: "tool",
    contributionSummary: "A safe publisher.",
    guideUrl: "https://example.com/repo",
  }, { nonceBase: 1700000000000, now: "2026-08-30T12:00:00.000Z" });
  const messages = {};
  for (const name of ["lobby", "announcement"]) {
    const expected = state.context.messages[name];
    messages[expected.room] = [{
      seq: name === "lobby" ? 10 : 11,
      ts: "2026-08-30T12:00:00.000Z",
      from: identity.did,
      nonce: Number(expected.nonce),
      text: expected.text,
      sig: sign(identity, expected.canonical),
    }];
  }
  const client = {
    readNote: async (ns) => ({
      body: ns.startsWith("did-")
        ? state.context.records.profile.value
        : state.context.records.contribution.value,
    }),
    readRoom: async (room) => ({ json: { messages: messages[room] } }),
  };
  const result = await auditState(state, client);
  assert.equal(result.ok, true);
  assert.equal(result.results.lobby.seq, 10);
  assert.equal(JSON.stringify(result).includes(identity.privateKeyJwk.d), false);
});

test("stops room verification when a public note was overwritten", async () => {
  const identity = generateIdentity();
  const state = prepareKit(identity, {
    agentName: "safeproof_agent",
    contributionType: "tool",
    contributionSummary: "A safe publisher.",
  }, { nonceBase: 1700000000000, now: "2026-08-30T12:00:00.000Z" });
  let roomReads = 0;
  const client = {
    readNote: async (ns) => ({ body: ns.startsWith("did-") ? state.context.records.profile.value : "tampered" }),
    readRoom: async () => { roomReads += 1; return { json: { messages: [] } }; },
  };
  const result = await auditState(state, client);
  assert.equal(result.ok, false);
  assert.equal(result.results.contribution.ok, false);
  assert.equal(roomReads, 0);
});

test("falls back to the retained export when a verified message leaves the tail window", async () => {
  const identity = generateIdentity();
  let state = prepareKit(identity, {
    agentName: "safeproof_agent",
    contributionType: "tool",
    contributionSummary: "A safe publisher.",
  }, { nonceBase: 1700000000000, now: "2026-08-30T12:00:00.000Z" });
  const messages = {};
  let tick = Date.parse(state.updatedAt);
  for (const name of OPERATION_ORDER) {
    if (!state.operations[name].enabled) continue;
    tick += 1;
    state = transitionOperation(state, name, "published", {
      at: new Date(tick).toISOString(),
      receipt: { httpStatus: 200 },
    });
    tick += 1;
    const expected = state.context.messages[name];
    const receipt = name === "contribution" || name === "profile"
      ? { sha256: state.context.records[name].digest }
      : {
          room: expected.room,
          seq: name === "lobby" ? 101 : 202,
          ts: new Date(tick).toISOString(),
          nonce: expected.nonce,
          sig: sign(identity, expected.canonical),
        };
    state = transitionOperation(state, name, "verified", {
      at: new Date(tick).toISOString(),
      receipt,
    });
    if (expected) messages[expected.room] = [{
      seq: receipt.seq,
      ts: receipt.ts,
      from: identity.did,
      nonce: Number(expected.nonce),
      text: expected.text,
      sig: receipt.sig,
    }];
  }
  const exports = [];
  const client = {
    readNote: async (ns) => ({
      body: ns.startsWith("did-")
        ? state.context.records.profile.value
        : state.context.records.contribution.value,
    }),
    readRoom: async () => ({ json: { messages: [] } }),
    readRoomExport: async (room, options) => {
      exports.push([room, options.seq]);
      return { json: { messages: messages[room] } };
    },
  };
  const result = await auditState(state, client);
  assert.equal(result.ok, true);
  assert.equal(result.results.lobby.source, "export");
  assert.deepEqual(exports, [["lobby", 101], ["technocore", 202]]);
});
