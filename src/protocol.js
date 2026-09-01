"use strict";

const crypto = require("node:crypto");

const TECHNOCORE_URL = "https://technocore.chat";
const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const NONCE_RE = /^[0-9]{1,19}$/;
const MESSAGE_LIMIT = 4096;
const NOTE_LIMIT = 8192;
const CONTRIBUTION_TYPES = Object.freeze(["tool", "guide", "video", "article", "agent", "prompt", "other"]);

function cleanText(value, limit = MESSAGE_LIMIT) {
  const text = String(value ?? "")
    .replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu, " ")
    .trim();
  if (!text) throw new Error("Text cannot be empty after the Technocore single-line sweep.");
  if (Array.from(text).length > limit) throw new Error(`Text is too long. Limit is ${limit} characters.`);
  return text;
}

function requireName(value, label = "Name") {
  const text = String(value ?? "").trim().toLowerCase();
  if (!NAME_RE.test(text)) throw new Error(`${label} must match ${NAME_RE}.`);
  return text;
}

function optionalHandle(value) {
  const text = String(value ?? "").trim().replace(/^@/, "");
  if (!text) return "";
  if (!/^[A-Za-z0-9_]{1,15}$/.test(text)) {
    throw new Error("X handle must be 1-15 letters, numbers, or underscores.");
  }
  return text;
}

function optionalUrl(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  const url = new URL(text);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Contribution URL must start with http:// or https://.");
  }
  if (url.username || url.password) throw new Error("Contribution URL must not contain credentials.");
  return url.toString();
}

function contributionType(value) {
  const text = String(value ?? "").trim().toLowerCase();
  if (!CONTRIBUTION_TYPES.includes(text)) {
    throw new Error(`Contribution type must be one of: ${CONTRIBUTION_TYPES.join(", ")}.`);
  }
  return text;
}

function normalizeBaseUrl(value = TECHNOCORE_URL) {
  const url = new URL(String(value).trim());
  const isLocal = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal)) {
    throw new Error("Technocore origin must use HTTPS (HTTP is allowed only on localhost).");
  }
  if (url.username || url.password || (url.pathname && url.pathname !== "/") || url.search || url.hash) {
    throw new Error("Technocore origin must not include credentials, a path, query, or fragment.");
  }
  return url.origin;
}

function validateFingerprint(value) {
  const text = String(value ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{16}$/.test(text)) throw new Error("Fingerprint must be 16 lowercase hex characters.");
  return text;
}

function shardedLocation(prefix, fingerprint) {
  const value = validateFingerprint(fingerprint);
  const ns = `${prefix}-${value.slice(0, 2)}`;
  const key = value.slice(2);
  return { ns, key, path: `/kv/${ns}/${key}` };
}

function didProfileLocation(fingerprint) {
  return shardedLocation("did", fingerprint);
}

function contributionLocation(fingerprint) {
  return shardedLocation("contrib", fingerprint);
}

function requireNonce(value) {
  const text = String(value ?? "");
  if (!NONCE_RE.test(text)) throw new Error("Nonce must be 1-19 ASCII digits.");
  return text;
}

function roomCanonical(room, nonce, value) {
  const cleanRoom = requireName(room, "Room");
  const cleanNonce = requireNonce(nonce);
  const text = cleanText(value, MESSAGE_LIMIT);
  return `${cleanRoom}|${cleanNonce}|${text}`;
}

function noteDigest(value) {
  return crypto.createHash("sha256").update(cleanText(value, NOTE_LIMIT), "utf8").digest("hex");
}

function requireDid(value) {
  const text = String(value ?? "").trim();
  if (!/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(text)) {
    throw new Error("DID must be an Ed25519 did:key value.");
  }
  return text;
}

function requireDigest(value) {
  const digest = String(value ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(digest)) throw new Error("Record digest must be a SHA-256 hex value.");
  return digest;
}

function requireRecordPath(value) {
  const text = String(value ?? "").trim();
  if (!/^\/kv\/[a-z0-9][a-z0-9_-]{0,47}\/[a-z0-9][a-z0-9_-]{0,47}$/.test(text)) {
    throw new Error("Record path must identify one Technocore note.");
  }
  return text;
}

function buildProfileValue(input) {
  const did = requireDid(input.did);
  const agentName = requireName(input.agentName, "Agent name");
  const contributionPath = requireRecordPath(input.contributionPath);
  const mailbox = input.mailbox ? requireName(input.mailbox, "Mailbox") : "";
  const xHandle = optionalHandle(input.xHandle);
  const guideUrl = optionalUrl(input.guideUrl);
  return cleanText([
    "technocore-profile-v1",
    `did:${did}`,
    `agent:${agentName}`,
    mailbox ? `mailbox:${mailbox}` : "",
    `contribution:${contributionPath}`,
    xHandle ? `x:@${xHandle}` : "",
    guideUrl ? `guide:${guideUrl}` : "",
  ].filter(Boolean).join(" "), NOTE_LIMIT);
}

function buildContributionValue(input) {
  const payload = {
    did: requireDid(input.did),
    agent: requireName(input.agentName, "Agent name"),
    type: contributionType(input.contributionType),
    url: optionalUrl(input.guideUrl),
    x: optionalHandle(input.xHandle),
    summary: cleanText(input.contributionSummary, 320),
  };
  return cleanText(`technocore-contribution-v2 ${JSON.stringify(payload)}`, NOTE_LIMIT);
}

function parseLegacyField(prefix, name) {
  const match = prefix.match(new RegExp(`(?:^|\\s)${name}:([^\\s]+)`));
  return match ? match[1] : "";
}

function parseContributionValue(value) {
  const text = cleanText(value, NOTE_LIMIT);
  const v2Prefix = "technocore-contribution-v2 ";
  if (text.startsWith(v2Prefix)) {
    let payload;
    try {
      payload = JSON.parse(text.slice(v2Prefix.length));
    } catch {
      throw new Error("Contribution v2 payload is not valid JSON.");
    }
    return {
      did: requireDid(payload.did),
      agentName: requireName(payload.agent, "Agent name"),
      contributionType: contributionType(payload.type),
      guideUrl: optionalUrl(payload.url),
      xHandle: optionalHandle(payload.x),
      contributionSummary: cleanText(payload.summary, 320),
      version: 2,
    };
  }

  if (!text.startsWith("technocore-contribution-v1 ")) {
    throw new Error("Unsupported contribution record format.");
  }
  const summaryMatch = /(?:^|\s)summary:/.exec(text);
  if (!summaryMatch) throw new Error("Legacy contribution record has no summary.");
  const summaryStart = summaryMatch.index + summaryMatch[0].length;
  const prefix = text.slice(0, summaryMatch.index);
  const suffix = text.slice(summaryStart);
  const laterField = /\s(?:url|x):/.exec(suffix);
  const isLegacySummaryFirst = Boolean(laterField);
  const summary = isLegacySummaryFirst ? suffix.slice(0, laterField.index) : suffix;
  const fields = isLegacySummaryFirst ? suffix.slice(laterField.index) : prefix;
  return {
    did: parseLegacyField(prefix, "did"),
    agentName: parseLegacyField(prefix, "agent"),
    contributionType: parseLegacyField(prefix, "type"),
    guideUrl: parseLegacyField(fields, "url"),
    xHandle: parseLegacyField(fields, "x").replace(/^@/, ""),
    contributionSummary: summary.trim(),
    version: 1,
  };
}

function buildLobbyValue(input) {
  return cleanText([
    "technocore-safeproof-checkin-v1",
    `agent:${requireName(input.agentName, "Agent name")}`,
    `did:${requireDid(input.did)}`,
    `profile:${requireRecordPath(input.profilePath)}`,
    `profile-sha256:${requireDigest(input.profileDigest)}`,
    `contribution:${requireRecordPath(input.contributionPath)}`,
    `contribution-sha256:${requireDigest(input.recordDigest)}`,
  ].join(" "), MESSAGE_LIMIT);
}

function buildAnnouncementValue(input) {
  const digest = requireDigest(input.recordDigest);
  return cleanText([
    "technocore-safeproof-announcement-v1",
    `agent:${requireName(input.agentName, "Agent name")}`,
    `did:${requireDid(input.did)}`,
    `type:${contributionType(input.contributionType)}`,
    `record:${requireRecordPath(input.recordPath)}`,
    `sha256:${digest}`,
    input.guideUrl ? `url:${optionalUrl(input.guideUrl)}` : "",
    input.xHandle ? `x:@${optionalHandle(input.xHandle)}` : "",
    `summary:${cleanText(input.contributionSummary, 320)}`,
  ].filter(Boolean).join(" "), MESSAGE_LIMIT);
}

function buildMailboxValue(input) {
  return cleanText([
    "technocore-safeproof-mailbox-v1",
    `agent:${requireName(input.agentName, "Agent name")}`,
    `did:${requireDid(input.did)}`,
    `profile:${requireRecordPath(input.profilePath)}`,
  ].join(" "), MESSAGE_LIMIT);
}

function encodeSegment(value) {
  return encodeURIComponent(String(value));
}

function buildNoteReadUrl(baseUrl, ns, key) {
  return `${normalizeBaseUrl(baseUrl)}/kv/${encodeSegment(requireName(ns, "Namespace"))}/${encodeSegment(requireName(key, "Key"))}`;
}

function buildNoteWriteUrl(baseUrl, ns, key, value) {
  return `${buildNoteReadUrl(baseUrl, ns, key)}/set/${encodeURIComponent(cleanText(value, NOTE_LIMIT))}`;
}

function buildSignedRoomWriteUrl(baseUrl, room, signedMessage) {
  const cleanRoom = requireName(room, "Room");
  const did = requireDid(signedMessage.did);
  const signature = String(signedMessage.sig || "");
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) throw new Error("Signature must be 86 base64url characters.");
  const nonce = requireNonce(signedMessage.nonce);
  const text = cleanText(signedMessage.text, MESSAGE_LIMIT);
  return `${normalizeBaseUrl(baseUrl)}/r/${encodeSegment(cleanRoom)}/say-signed/${encodeSegment(did)}/${encodeSegment(signature)}/${nonce}/${encodeURIComponent(text)}`;
}

function buildRoomReadUrl(baseUrl, room, options = {}) {
  const url = new URL(`/r/${encodeSegment(requireName(room, "Room"))}`, normalizeBaseUrl(baseUrl));
  url.searchParams.set("format", "json");
  if (options.since !== undefined) url.searchParams.set("since", String(options.since));
  url.searchParams.set("limit", String(options.limit || 200));
  if (options.cacheBust !== undefined) url.searchParams.set("n", String(options.cacheBust));
  return url.toString();
}

function buildRoomExportUrl(baseUrl, room) {
  return `${normalizeBaseUrl(baseUrl)}/r/${encodeSegment(requireName(room, "Room"))}/export`;
}

function extractStoredNote(responseBody) {
  const text = String(responseBody ?? "").replace(/\r\n/g, "\n");
  const withoutBudget = (value) => value.replace(/\n# budget: [^\n]*(?:\n[\s\S]*)?$/, "").trim();
  if (!text.startsWith("!! UNTRUSTED CONTENT")) return withoutBudget(text);
  const separator = text.indexOf("\n\n");
  return withoutBudget(separator >= 0 ? text.slice(separator + 2) : "");
}

module.exports = {
  CONTRIBUTION_TYPES,
  MESSAGE_LIMIT,
  NAME_RE,
  NONCE_RE,
  NOTE_LIMIT,
  TECHNOCORE_URL,
  buildAnnouncementValue,
  buildContributionValue,
  buildLobbyValue,
  buildMailboxValue,
  buildNoteReadUrl,
  buildNoteWriteUrl,
  buildProfileValue,
  buildRoomExportUrl,
  buildRoomReadUrl,
  buildSignedRoomWriteUrl,
  cleanText,
  contributionLocation,
  contributionType,
  didProfileLocation,
  extractStoredNote,
  normalizeBaseUrl,
  noteDigest,
  optionalHandle,
  optionalUrl,
  parseContributionValue,
  requireName,
  roomCanonical,
  validateFingerprint,
};
