"use strict";

const { importIdentity, sign, validatePublicIdentity, verify } = require("./identity");
const { TechnocoreError } = require("./client");
const { assertPlanContext } = require("./kit");
const { extractStoredNote, noteDigest, roomCanonical } = require("./protocol");
const { nextOperation, transitionOperation } = require("./state");

function safeAt(state, now) {
  const candidate = new Date(now()).toISOString();
  return candidate < state.updatedAt ? state.updatedAt : candidate;
}

function messageForOperation(context, operation) {
  if (operation === "announcement") return context.messages.announcement;
  return context.messages[operation];
}

function recordForOperation(context, operation) {
  return context.records[operation];
}

function messagesFromRoomResponse(response) {
  const json = response && response.json;
  if (!json || !Array.isArray(json.messages)) return [];
  return json.messages;
}

function validServerTimestamp(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && !Number.isNaN(Date.parse(value));
}

function matchingRoomReceipt(response, expected, identity) {
  const publicIdentity = validatePublicIdentity(identity);
  const canonical = roomCanonical(expected.room, expected.nonce, expected.text);
  if (expected.canonical !== canonical) return null;
  const message = messagesFromRoomResponse(response).find((entry) => (
    entry
    && entry.from === publicIdentity.did
    && String(entry.nonce) === expected.nonce
    && entry.text === expected.text
    && typeof entry.sig === "string"
    && Number.isSafeInteger(entry.seq)
    && entry.seq > 0
    && validServerTimestamp(entry.ts)
    && verify(publicIdentity.publicKeyJwk, canonical, entry.sig)
  ));
  if (!message) return null;
  return {
    room: expected.room,
    seq: message.seq,
    ts: message.ts || "",
    nonce: expected.nonce,
    sig: message.sig,
  };
}

class SafePublisher {
  constructor(client, options = {}) {
    this.client = client;
    this.now = options.now || Date.now;
    this.onState = options.onState || (async () => {});
  }

  async transition(state, operation, status, options = {}) {
    const next = transitionOperation(state, operation, status, {
      ...options,
      at: options.at || safeAt(state, this.now),
    });
    await this.onState(next);
    return next;
  }

  assertIdentity(state, identity) {
    assertPlanContext(state);
    let privateIdentity;
    try {
      privateIdentity = importIdentity(identity && identity.privateKeyJwk);
    } catch {
      throw new Error("Loaded private identity is invalid.");
    }
    const expected = validatePublicIdentity(state.context.identity);
    if (
      privateIdentity.did !== expected.did
      || privateIdentity.fingerprint !== expected.fingerprint
      || privateIdentity.publicKeyJwk.x !== expected.publicKeyJwk.x
    ) {
      throw new Error("Loaded private identity does not match the prepared SafeProof state.");
    }
  }

  async findNote(state, operation) {
    const record = recordForOperation(state.context, operation);
    try {
      const response = await this.client.readNote(record.ns, record.key);
      const stored = extractStoredNote(response.body);
      if (stored !== record.value || noteDigest(stored) !== record.digest) {
        return { found: true, matches: false, response };
      }
      return { found: true, matches: true, response };
    } catch (error) {
      if (error instanceof TechnocoreError && error.status === 404) return { found: false, matches: false };
      throw error;
    }
  }

  async verifyNote(state, operation) {
    const record = recordForOperation(state.context, operation);
    const found = await this.findNote(state, operation);
    if (!found.found || !found.matches) return { state, verified: false, collision: found.found };
    let next = state;
    const current = next.operations[operation].status;
    if (["prepared", "unknown"].includes(current)) {
      next = await this.transition(next, operation, "published", {
        receipt: { recoveredByReadBack: true, httpStatus: found.response.status },
      });
    }
    if (next.operations[operation].status === "published") {
      next = await this.transition(next, operation, "verified", {
        receipt: { readUrl: record.readUrl, sha256: record.digest },
      });
    }
    return { state: next, verified: true, collision: false };
  }

  async publishNote(state, operation) {
    const initialStatus = state.operations[operation].status;
    const checked = await this.verifyNote(state, operation);
    if (checked.verified) return checked.state;
    if (checked.collision) {
      if (initialStatus === "published") return state;
      return this.transition(state, operation, "failed", {
        error: "The target Technocore note already contains a different value.",
      });
    }
    if (initialStatus === "unknown") return state;
    if (initialStatus === "published") return state;
    const record = recordForOperation(state.context, operation);
    let next = state;
    try {
      const response = await this.client.writeNote(record.ns, record.key, record.value, { ifAbsent: true });
      const acknowledged = /^ok(?:\s|$)/i.test(response.body.trim());
      if (!acknowledged) {
        const recovered = await this.verifyNote(next, operation).catch(() => ({ state: next, verified: false }));
        if (recovered.verified) return recovered.state;
        return this.transition(next, operation, "unknown", {
          receipt: { outcome: "complete-unrecognized-response", httpStatus: response.status },
        });
      }
      next = await this.transition(next, operation, "published", {
        receipt: { httpStatus: response.status, acknowledged: true },
      });
    } catch (error) {
      if (error instanceof TechnocoreError && error.outcome === "unknown") {
        next = await this.transition(next, operation, "unknown", {
          receipt: {
            outcome: "uncertain",
            message: error.message,
            httpStatus: error.status || 0,
            retryAfter: error.retryAfter || "",
          },
        });
        const recovered = await this.verifyNote(next, operation).catch(() => ({ state: next, verified: false }));
        return recovered.state;
      }
      if (error instanceof TechnocoreError && error.status === 409) {
        const recovered = await this.verifyNote(next, operation).catch(() => ({ state: next, verified: false }));
        if (recovered.verified) return recovered.state;
      }
      return this.transition(next, operation, "failed", {
        error: error.message,
        receipt: {
          httpStatus: error instanceof TechnocoreError ? error.status : 0,
          retryAfter: error instanceof TechnocoreError ? error.retryAfter : "",
        },
      });
    }
    const verified = await this.verifyNote(next, operation);
    if (!verified.verified) {
      return next;
    }
    return verified.state;
  }

  async findRoomMessage(state, operation, identity) {
    const expected = messageForOperation(state.context, operation);
    const response = await this.client.readRoom(expected.room, { limit: 200 });
    return matchingRoomReceipt(response, expected, identity);
  }

  async verifyRoomMessage(state, operation, identity) {
    const receipt = await this.findRoomMessage(state, operation, identity);
    if (!receipt) return { state, verified: false };
    let next = state;
    if (["prepared", "unknown"].includes(next.operations[operation].status)) {
      next = await this.transition(next, operation, "published", {
        receipt: { recoveredByReadBack: true, room: receipt.room, seq: receipt.seq },
      });
    }
    if (next.operations[operation].status === "published") {
      next = await this.transition(next, operation, "verified", { receipt });
    }
    return { state: next, verified: true };
  }

  async publishRoomMessage(state, operation, identity) {
    const initialStatus = state.operations[operation].status;
    const checked = await this.verifyRoomMessage(state, operation, identity);
    if (checked.verified) return checked.state;
    if (initialStatus === "unknown") return state;
    if (initialStatus === "published") return state;
    const expected = messageForOperation(state.context, operation);
    const canonical = roomCanonical(expected.room, expected.nonce, expected.text);
    if (canonical !== expected.canonical) {
      throw new Error("Prepared room canonical value is inconsistent.");
    }
    const signature = sign(identity.privateKeyJwk, canonical);
    let next = state;
    try {
      const response = await this.client.writeSignedRoom(expected.room, {
        did: identity.did,
        sig: signature,
        nonce: expected.nonce,
        text: expected.text,
      });
      const acknowledged = /^ok(?:\s|$)/i.test(response.body.trim());
      if (!acknowledged) {
        const recovered = await this.verifyRoomMessage(next, operation, identity)
          .catch(() => ({ state: next, verified: false }));
        if (recovered.verified) return recovered.state;
        return this.transition(next, operation, "unknown", {
          receipt: { outcome: "complete-unrecognized-response", httpStatus: response.status },
        });
      }
      next = await this.transition(next, operation, "published", {
        receipt: { httpStatus: response.status, acknowledged: true },
      });
    } catch (error) {
      if (error instanceof TechnocoreError && error.outcome === "unknown") {
        next = await this.transition(next, operation, "unknown", {
          receipt: {
            outcome: "uncertain",
            message: error.message,
            httpStatus: error.status || 0,
            retryAfter: error.retryAfter || "",
          },
        });
        const recovered = await this.verifyRoomMessage(next, operation, identity)
          .catch(() => ({ state: next, verified: false }));
        return recovered.state;
      }
      if (error instanceof TechnocoreError && error.status === 409) {
        const recovered = await this.verifyRoomMessage(next, operation, identity)
          .catch(() => ({ state: next, verified: false }));
        if (recovered.verified) return recovered.state;
      }
      return this.transition(next, operation, "failed", {
        error: error.message,
        receipt: {
          httpStatus: error instanceof TechnocoreError ? error.status : 0,
          retryAfter: error instanceof TechnocoreError ? error.retryAfter : "",
        },
      });
    }
    const verified = await this.verifyRoomMessage(next, operation, identity);
    if (!verified.verified) {
      return next;
    }
    return verified.state;
  }

  async publishNext(state, identity) {
    this.assertIdentity(state, identity);
    const operation = nextOperation(state);
    if (!operation) return state;
    const status = state.operations[operation].status;
    if (status === "failed") {
      throw new Error(`Operation ${operation} is failed; explicitly reset it to prepared before retrying.`);
    }
    const noteDependencies = operation === "contribution"
      ? []
      : operation === "profile"
        ? ["contribution"]
        : ["contribution", "profile"];
    for (const recordName of noteDependencies) {
      const checked = await this.findNote(state, recordName);
      if (!checked.found || !checked.matches) {
        if (["unknown", "published"].includes(status)) return state;
        return this.transition(state, operation, "failed", {
          error: `The ${recordName} note is missing or changed; ${operation} was not published.`,
        });
      }
    }
    const roomDependencies = operation === "announcement"
      ? ["lobby"]
      : operation === "mailbox"
        ? ["lobby", "announcement"]
        : [];
    for (const messageName of roomDependencies) {
      const receipt = await this.findRoomMessage(state, messageName, identity);
      if (!receipt) {
        if (["unknown", "published"].includes(status)) return state;
        return this.transition(state, operation, "failed", {
          error: `The signed ${messageName} message was not found; ${operation} was not published.`,
        });
      }
    }
    if (["profile", "contribution"].includes(operation)) {
      return this.publishNote(state, operation);
    }
    return this.publishRoomMessage(state, operation, identity);
  }

  async publishAll(state, identity) {
    let next = state;
    while (nextOperation(next)) {
      const before = next;
      next = await this.publishNext(next, identity);
      const current = nextOperation(next);
      if (next === before || (current && ["failed", "unknown"].includes(next.operations[current].status))) break;
    }
    return next;
  }
}

module.exports = {
  SafePublisher,
  matchingRoomReceipt,
};
