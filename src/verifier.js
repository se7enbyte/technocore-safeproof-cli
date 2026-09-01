"use strict";

const { extractStoredNote, noteDigest } = require("./protocol");
const { matchingRoomReceipt } = require("./publisher");
const { assertPlanContext } = require("./kit");
const { OPERATION_ORDER, assertState } = require("./state");

async function auditNote(client, record) {
  try {
    const response = await client.readNote(record.ns, record.key);
    const stored = extractStoredNote(response.body);
    const digest = noteDigest(stored);
    return {
      ok: stored === record.value && digest === record.digest,
      found: true,
      expectedSha256: record.digest,
      actualSha256: digest,
      readUrl: record.readUrl,
    };
  } catch (error) {
    return { ok: false, found: false, error: error.message, readUrl: record.readUrl };
  }
}

async function auditRoom(client, expected, identity, options = {}) {
  try {
    let response = await client.readRoom(expected.room, {
      limit: 200,
      since: Number.isSafeInteger(options.seq) && options.seq > 0 ? Math.max(0, options.seq - 1) : undefined,
    });
    let receipt = matchingRoomReceipt(response, expected, identity);
    let source = "tail";
    if (
      !receipt
      && Number.isSafeInteger(options.seq)
      && options.seq > 0
      && typeof client.readRoomExport === "function"
    ) {
      response = await client.readRoomExport(expected.room, { seq: options.seq });
      receipt = matchingRoomReceipt(response, expected, identity);
      source = "export";
    }
    return receipt
      ? { ok: true, found: true, source, ...receipt }
      : { ok: false, found: false, room: expected.room, error: "Matching signed message was not found." };
  } catch (error) {
    return { ok: false, found: false, room: expected.room, error: error.message };
  }
}

async function auditState(state, client) {
  assertState(state);
  assertPlanContext(state);
  const identity = state.context.identity;
  const results = {
    profile: await auditNote(client, state.context.records.profile),
    contribution: await auditNote(client, state.context.records.contribution),
  };
  if (!results.profile.ok || !results.contribution.ok) {
    return { ok: false, checkedAt: new Date().toISOString(), results };
  }
  for (const name of ["lobby", "announcement", ...(state.includeMailbox ? ["mailbox"] : [])]) {
    const expected = name === "announcement" ? state.context.messages.announcement : state.context.messages[name];
    const receipt = [...state.operations[name].receipts]
      .reverse()
      .find((entry) => entry.status === "verified")?.data;
    results[name] = await auditRoom(client, expected, identity, { seq: receipt?.seq });
  }
  const required = OPERATION_ORDER.filter((name) => state.operations[name].enabled);
  return {
    ok: required.every((name) => results[name]?.ok === true),
    checkedAt: new Date().toISOString(),
    results,
  };
}

module.exports = {
  auditNote,
  auditRoom,
  auditState,
};
