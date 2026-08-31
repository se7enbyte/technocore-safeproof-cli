"use strict";

const crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const {
  importIdentity,
  sign,
  validatePublicIdentity,
  verify,
} = require("./identity");
const {
  TECHNOCORE_URL,
  buildAnnouncementValue,
  buildContributionValue,
  buildLobbyValue,
  buildMailboxValue,
  buildNoteReadUrl,
  buildProfileValue,
  cleanText,
  contributionLocation,
  contributionType,
  didProfileLocation,
  normalizeBaseUrl,
  noteDigest,
  optionalHandle,
  optionalUrl,
  requireName,
  roomCanonical,
} = require("./protocol");
const { createState, transitionOperation } = require("./state");

const PLAN_AUTH_SCHEME = "safeproof-plan-ed25519-sha256-v1";

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(",")}}`;
  }
  throw new TypeError("Plan contains a non-JSON value.");
}

function planDigest(context) {
  return crypto.createHash("sha256").update(canonicalJson(context), "utf8").digest("hex");
}

function planSigningMessage(digest) {
  return `${PLAN_AUTH_SCHEME}|${digest}`;
}

function mailboxName(randomBytes = crypto.randomBytes) {
  return `mb-p-${randomBytes(12).toString("hex")}`;
}

function nonceBase(value) {
  const number = value === undefined ? Date.now() : Number(value);
  if (!Number.isSafeInteger(number) || number <= 0 || number > Number.MAX_SAFE_INTEGER - 2) {
    throw new Error("Nonce base must leave room for two safe sequential nonces.");
  }
  return number;
}

function nonceSequence(value, includeMailbox) {
  const text = String(value ?? "");
  if (!/^[0-9]{1,19}$/.test(text)) throw new Error("Lobby nonce must be 1-19 ASCII digits.");
  const base = BigInt(text);
  if (base <= 0n) throw new Error("Lobby nonce must be positive.");
  const announcement = (base + 1n).toString();
  const mailbox = (base + 2n).toString();
  if (announcement.length > 19 || (includeMailbox && mailbox.length > 19)) {
    throw new Error("Sequential nonce exceeds the 19-digit limit.");
  }
  return { lobby: base.toString(), announcement, mailbox };
}

function buildUnsignedContext(identity, input = {}) {
  const publicIdentity = validatePublicIdentity(identity);
  const baseUrl = normalizeBaseUrl(input.baseUrl || TECHNOCORE_URL);
  const agentName = requireName(input.agentName, "Agent name");
  const type = contributionType(input.contributionType);
  const contributionSummary = cleanText(input.contributionSummary, 320);
  const guideUrl = optionalUrl(input.guideUrl);
  const xHandle = optionalHandle(input.xHandle);
  const includeMailbox = input.includeMailbox === true;
  const mailbox = includeMailbox ? requireName(input.mailbox, "Mailbox") : "";
  const nonces = nonceSequence(input.lobbyNonce, includeMailbox);
  const profileLocation = didProfileLocation(publicIdentity.fingerprint);
  const recordLocation = contributionLocation(publicIdentity.fingerprint);

  const contributionValue = buildContributionValue({
    did: publicIdentity.did,
    agentName,
    contributionType: type,
    contributionSummary,
    guideUrl,
    xHandle,
  });
  const recordDigest = noteDigest(contributionValue);
  const profileValue = buildProfileValue({
    did: publicIdentity.did,
    agentName,
    contributionPath: recordLocation.path,
    mailbox,
    guideUrl,
    xHandle,
  });
  const profileDigest = noteDigest(profileValue);
  const lobbyText = buildLobbyValue({
    did: publicIdentity.did,
    agentName,
    profilePath: profileLocation.path,
    profileDigest,
    contributionPath: recordLocation.path,
    recordDigest,
  });
  const announcementText = buildAnnouncementValue({
    did: publicIdentity.did,
    agentName,
    contributionType: type,
    contributionSummary,
    guideUrl,
    xHandle,
    recordPath: recordLocation.path,
    recordDigest,
  });
  const mailboxText = mailbox ? buildMailboxValue({
    did: publicIdentity.did,
    agentName,
    profilePath: profileLocation.path,
  }) : "";

  return {
    baseUrl,
    identity: publicIdentity,
    contribution: {
      agentName,
      contributionType: type,
      contributionSummary,
      guideUrl,
      xHandle,
      mailbox,
    },
    records: {
      profile: {
        ...profileLocation,
        readUrl: buildNoteReadUrl(baseUrl, profileLocation.ns, profileLocation.key),
        value: profileValue,
        digest: profileDigest,
      },
      contribution: {
        ...recordLocation,
        readUrl: buildNoteReadUrl(baseUrl, recordLocation.ns, recordLocation.key),
        value: contributionValue,
        digest: recordDigest,
      },
    },
    messages: {
      lobby: {
        room: "lobby",
        nonce: nonces.lobby,
        text: lobbyText,
        canonical: roomCanonical("lobby", nonces.lobby, lobbyText),
      },
      announcement: {
        room: "technocore",
        nonce: nonces.announcement,
        text: announcementText,
        canonical: roomCanonical("technocore", nonces.announcement, announcementText),
      },
      mailbox: mailbox ? {
        room: mailbox,
        nonce: nonces.mailbox,
        text: mailboxText,
        canonical: roomCanonical(mailbox, nonces.mailbox, mailboxText),
      } : null,
    },
  };
}

function authorizeContext(unsignedContext, identity) {
  const sha256 = planDigest(unsignedContext);
  return {
    ...unsignedContext,
    authorization: {
      scheme: PLAN_AUTH_SCHEME,
      sha256,
      sig: sign(identity.privateKeyJwk, planSigningMessage(sha256)),
    },
  };
}

function assertPlanContext(state) {
  if (!state || typeof state !== "object" || !state.context) {
    throw new Error("SafeProof state has no plan context.");
  }
  const { authorization, ...unsignedContext } = state.context;
  if (!authorization || typeof authorization !== "object" || Array.isArray(authorization)) {
    throw new Error("SafeProof plan authorization is missing.");
  }
  if (Object.keys(authorization).sort().join(",") !== "scheme,sha256,sig") {
    throw new Error("SafeProof plan authorization has unexpected fields.");
  }
  const contribution = unsignedContext.contribution || {};
  const messages = unsignedContext.messages || {};
  const expected = buildUnsignedContext(unsignedContext.identity, {
    baseUrl: unsignedContext.baseUrl,
    agentName: contribution.agentName,
    contributionType: contribution.contributionType,
    contributionSummary: contribution.contributionSummary,
    guideUrl: contribution.guideUrl,
    xHandle: contribution.xHandle,
    includeMailbox: state.includeMailbox,
    mailbox: contribution.mailbox,
    lobbyNonce: messages.lobby && messages.lobby.nonce,
  });
  if (!isDeepStrictEqual(unsignedContext, expected)) {
    throw new Error("SafeProof plan context is inconsistent or has been modified.");
  }
  const sha256 = planDigest(unsignedContext);
  if (authorization.scheme !== PLAN_AUTH_SCHEME || authorization.sha256 !== sha256) {
    throw new Error("SafeProof plan digest is invalid.");
  }
  if (!verify(unsignedContext.identity.publicKeyJwk, planSigningMessage(sha256), authorization.sig)) {
    throw new Error("SafeProof plan signature is invalid.");
  }
  return state;
}

function prepareKit(identity, input = {}, options = {}) {
  const privateIdentity = importIdentity(identity && identity.privateKeyJwk);
  if (identity.did !== privateIdentity.did || identity.fingerprint !== privateIdentity.fingerprint) {
    throw new Error("Supplied identity metadata does not match its private key.");
  }
  const includeMailbox = input.includeMailbox === true;
  const mailbox = includeMailbox
    ? (input.mailbox ? requireName(input.mailbox, "Mailbox") : mailboxName(options.randomBytes))
    : "";
  const baseNonce = nonceBase(options.nonceBase);
  const at = new Date(options.now || Date.now()).toISOString();
  const unsignedContext = buildUnsignedContext(privateIdentity, {
    ...input,
    includeMailbox,
    mailbox,
    lobbyNonce: String(baseNonce),
  });
  const context = authorizeContext(unsignedContext, privateIdentity);

  let state = createState({ at, includeMailbox, context });
  for (const name of ["contribution", "profile", "lobby", "announcement", ...(includeMailbox ? ["mailbox"] : [])]) {
    state = transitionOperation(state, name, "prepared", { at });
  }
  return assertPlanContext(state);
}

module.exports = {
  PLAN_AUTH_SCHEME,
  assertPlanContext,
  buildUnsignedContext,
  canonicalJson,
  mailboxName,
  nonceBase,
  planDigest,
  prepareKit,
};
