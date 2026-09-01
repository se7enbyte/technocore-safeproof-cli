"use strict";

const { buildRoomExportUrl, buildRoomReadUrl } = require("./protocol");
const { assertPlanContext } = require("./kit");
const { OPERATION_ORDER, assertNoSecrets, assertState } = require("./state");

function lastReceipt(operation, status) {
  return [...operation.receipts].reverse().find((receipt) => receipt.status === status)?.data || null;
}

function proofStatus(state, audit = null) {
  const enabled = OPERATION_ORDER.filter((name) => state.operations[name].enabled);
  if (enabled.every((name) => ["pending", "prepared"].includes(state.operations[name].status))) return "prepared";
  if (audit?.ok === true && enabled.every((name) => state.operations[name].status === "verified")) return "verified";
  if (enabled.some((name) => ["published", "verified", "unknown", "failed"].includes(state.operations[name].status))) {
    return "partial";
  }
  return "prepared";
}

function roomProof(state, name) {
  const operation = state.operations[name];
  if (!operation.enabled) return null;
  const message = name === "announcement"
    ? state.context.messages.announcement
    : state.context.messages[name];
  const receipt = lastReceipt(operation, "verified");
  return {
    status: operation.status,
    room: message.room,
    readUrl: buildRoomReadUrl(state.context.baseUrl, message.room, {
      limit: 200,
      since: Number.isSafeInteger(receipt?.seq) && receipt.seq > 0 ? Math.max(0, receipt.seq - 1) : undefined,
    }),
    exportUrl: buildRoomExportUrl(state.context.baseUrl, message.room),
    seq: receipt?.seq ?? null,
    ts: receipt?.ts || "",
    nonce: message.nonce,
    text: message.text,
    sig: receipt?.sig || "",
  };
}

function createPublicProof(state, options = {}) {
  assertState(state);
  assertPlanContext(state);
  const audit = options.audit || null;
  const proof = {
    schema: "technocore-safeproof",
    version: 1,
    status: proofStatus(state, audit),
    generatedAt: audit?.checkedAt || state.updatedAt,
    identity: {
      did: state.context.identity.did,
      fingerprint: state.context.identity.fingerprint,
      publicKeyJwk: state.context.identity.publicKeyJwk,
    },
    contribution: { ...state.context.contribution },
    planAuthorization: { ...state.context.authorization },
    liveAudit: audit ? JSON.parse(JSON.stringify(audit)) : {
      ok: false,
      checkedAt: null,
      status: "not-run",
    },
    records: {
      profile: {
        status: state.operations.profile.status,
        readUrl: state.context.records.profile.readUrl,
        sha256: state.context.records.profile.digest,
      },
      contribution: {
        status: state.operations.contribution.status,
        readUrl: state.context.records.contribution.readUrl,
        sha256: state.context.records.contribution.digest,
      },
    },
    signedMessages: {
      lobby: roomProof(state, "lobby"),
      announcement: roomProof(state, "announcement"),
      mailbox: roomProof(state, "mailbox"),
    },
  };
  assertNoSecrets(proof);
  return proof;
}

function markdownForProof(proof) {
  const statusNotice = proof.status === "verified"
    ? "Live read-back audit passed; the records and signed messages matched at the checked time."
    : proof.status === "prepared"
      ? "Publication plan only — nothing here is evidence that Technocore publication occurred."
      : "Incomplete or not currently verified — do not present this artifact as completed publication proof.";
  const lines = [
    "# Technocore SafeProof",
    "",
    `- Status: ${proof.status}`,
    `- Notice: ${statusNotice}`,
    `- Live audit checked at: ${proof.liveAudit.checkedAt || "not run"}`,
    `- Agent: ${proof.contribution.agentName}`,
    `- DID: ${proof.identity.did}`,
    `- Fingerprint: ${proof.identity.fingerprint}`,
    `- Authorized plan SHA-256: ${proof.planAuthorization.sha256}`,
    `- Contribution type: ${proof.contribution.contributionType}`,
    `- Contribution: ${proof.contribution.contributionSummary}`,
    proof.contribution.guideUrl ? `- Contribution URL: ${proof.contribution.guideUrl}` : "",
    proof.contribution.xHandle ? `- X: @${proof.contribution.xHandle}` : "",
    `- Profile record: ${proof.records.profile.readUrl}`,
    `- Profile SHA-256: ${proof.records.profile.sha256}`,
    `- Contribution record: ${proof.records.contribution.readUrl}`,
    `- Contribution SHA-256: ${proof.records.contribution.sha256}`,
    "",
    "## Signed messages",
    "",
  ].filter(Boolean);
  for (const [label, message] of Object.entries(proof.signedMessages)) {
    if (!message) continue;
    lines.push(`- ${label}: ${message.status}${message.seq !== null ? ` (room ${message.room}, seq ${message.seq})` : ""}`);
    lines.push(`  - Retained export: ${message.exportUrl}`);
  }
  lines.push(
    "",
    statusNotice,
    "It does not guarantee FLOP rewards, token allocation, or airdrop eligibility.",
    "",
  );
  return lines.join("\n");
}

function serializePublicProof(state, options = {}) {
  const proof = createPublicProof(state, options);
  return {
    proof,
    json: `${JSON.stringify(proof, null, 2)}\n`,
    markdown: markdownForProof(proof),
  };
}

module.exports = {
  createPublicProof,
  markdownForProof,
  proofStatus,
  serializePublicProof,
};
