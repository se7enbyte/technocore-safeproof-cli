"use strict";

const STATE_SCHEMA = "safeproof-operation-state";
const STATE_VERSION = 1;
const OPERATION_ORDER = Object.freeze([
  "contribution",
  "profile",
  "lobby",
  "announcement",
  "mailbox",
]);
const OPERATION_STATUSES = Object.freeze([
  "pending",
  "prepared",
  "published",
  "verified",
  "failed",
  "unknown",
]);
const ALLOWED_TRANSITIONS = Object.freeze({
  pending: Object.freeze(["prepared", "failed"]),
  prepared: Object.freeze(["published", "failed", "unknown"]),
  unknown: Object.freeze(["prepared", "published", "failed"]),
  published: Object.freeze(["verified"]),
  verified: Object.freeze([]),
  failed: Object.freeze(["prepared"]),
});

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function decoded(value) {
  let result = value;
  for (let index = 0; index < 3; index += 1) {
    try {
      const next = decodeURIComponent(result);
      if (next === result) break;
      result = next;
    } catch {
      break;
    }
  }
  return result.toLowerCase();
}

function isSignatureBearingWriteUrl(value) {
  if (typeof value !== "string") return false;
  const normalized = decoded(value);
  const looksLikeUrl = /^(?:https?:\/\/|\/)/.test(normalized);
  if (!looksLikeUrl) return false;
  return normalized.includes("/say-signed/")
    || normalized.includes("/write-signed/")
    || normalized.includes("/signed-write/")
    || /[?&](?:sig|signature)=/.test(normalized);
}

function isSecretKey(key) {
  const normalized = String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
  return normalized === "d"
    || normalized.includes("privatekey")
    || normalized.includes("seed");
}

function assertNoSecrets(value, path = "$", seen = new Set()) {
  if (typeof value === "string") {
    if (isSignatureBearingWriteUrl(value)) {
      throw new TypeError(`Signature-bearing write URL is not allowed at ${path}`);
    }
    return true;
  }
  if (value === null || typeof value !== "object") return true;
  if (seen.has(value)) throw new TypeError(`Circular value is not allowed at ${path}`);
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoSecrets(entry, `${path}[${index}]`, seen));
  } else {
    for (const key of Object.keys(value)) {
      if (isSecretKey(key)) throw new TypeError(`Secret field ${path}.${key} is not allowed`);
      assertNoSecrets(value[key], `${path}.${key}`, seen);
    }
  }
  seen.delete(value);
  return true;
}

function assertJsonValue(value, path = "$", seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`Non-finite number at ${path}`);
    return;
  }
  if (typeof value !== "object") throw new TypeError(`Non-JSON value at ${path}`);
  if (seen.has(value)) throw new TypeError(`Circular value at ${path}`);
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertJsonValue(entry, `${path}[${index}]`, seen));
  } else {
    if (!isPlainObject(value)) throw new TypeError(`Non-plain object at ${path}`);
    for (const [key, entry] of Object.entries(value)) {
      assertJsonValue(entry, `${path}.${key}`, seen);
    }
  }
  seen.delete(value);
}

function cloneJson(value) {
  assertJsonValue(value);
  assertNoSecrets(value);
  return JSON.parse(JSON.stringify(value));
}

function isoTimestamp(value = new Date()) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new TypeError("Invalid timestamp");
  return date.toISOString();
}

function assertTimestamp(value, path) {
  let normalized;
  try {
    normalized = typeof value === "string" ? isoTimestamp(value) : null;
  } catch {
    normalized = null;
  }
  if (normalized !== value) {
    throw new TypeError(`Invalid timestamp at ${path}`);
  }
}

function assertExactKeys(value, expected, path) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`Unexpected fields at ${path}`);
  }
}

function operationState(enabled, at) {
  return {
    enabled,
    status: "pending",
    statusAt: at,
    timestamps: {
      prepared: null,
      published: null,
      verified: null,
      failed: null,
      unknown: null,
    },
    receipts: [],
    error: null,
  };
}

function createState(options = {}) {
  if (!isPlainObject(options)) throw new TypeError("State options must be an object");
  if (options.includeMailbox !== undefined && typeof options.includeMailbox !== "boolean") {
    throw new TypeError("includeMailbox must be a boolean");
  }
  const at = isoTimestamp(options.at);
  const includeMailbox = options.includeMailbox === true;
  const rawContext = options.context === undefined ? {} : options.context;
  if (!isPlainObject(rawContext)) throw new TypeError("State context must be an object");
  const context = cloneJson(rawContext);
  const operations = {};
  for (const name of OPERATION_ORDER) {
    operations[name] = operationState(name !== "mailbox" || includeMailbox, at);
  }
  return {
    schema: STATE_SCHEMA,
    version: STATE_VERSION,
    createdAt: at,
    updatedAt: at,
    includeMailbox,
    context,
    operations,
  };
}

function assertOperation(operation, name, state) {
  const path = `$.operations.${name}`;
  if (!isPlainObject(operation)) throw new TypeError(`Invalid operation at ${path}`);
  assertExactKeys(operation, [
    "enabled", "status", "statusAt", "timestamps", "receipts", "error",
  ], path);
  if (typeof operation.enabled !== "boolean") throw new TypeError(`Invalid enabled flag at ${path}`);
  const expectedEnabled = name !== "mailbox" || state.includeMailbox;
  if (operation.enabled !== expectedEnabled) throw new TypeError(`Inconsistent enabled flag at ${path}`);
  if (!OPERATION_STATUSES.includes(operation.status)) throw new TypeError(`Invalid status at ${path}`);
  if (!operation.enabled && operation.status !== "pending") {
    throw new TypeError(`Disabled operation must remain pending at ${path}`);
  }
  assertTimestamp(operation.statusAt, `${path}.statusAt`);
  if (!isPlainObject(operation.timestamps)) throw new TypeError(`Invalid timestamps at ${path}`);
  assertExactKeys(operation.timestamps, ["prepared", "published", "verified", "failed", "unknown"], `${path}.timestamps`);
  for (const status of ["prepared", "published", "verified", "failed", "unknown"]) {
    const timestamp = operation.timestamps[status];
    if (timestamp !== null) assertTimestamp(timestamp, `${path}.timestamps.${status}`);
    if (timestamp !== null && timestamp > state.updatedAt) {
      throw new TypeError(`Operation timestamp exceeds updatedAt at ${path}`);
    }
  }
  if (operation.statusAt > state.updatedAt) throw new TypeError(`statusAt exceeds updatedAt at ${path}`);
  if (operation.status === "pending") {
    if (Object.values(operation.timestamps).some((timestamp) => timestamp !== null)) {
      throw new TypeError(`Pending operation cannot have status timestamps at ${path}`);
    }
  } else if (operation.timestamps[operation.status] !== operation.statusAt) {
    throw new TypeError(`Current status timestamp mismatch at ${path}`);
  }
  if (!Array.isArray(operation.receipts)) throw new TypeError(`Invalid receipts at ${path}`);
  for (const [index, receipt] of operation.receipts.entries()) {
    if (!isPlainObject(receipt)) throw new TypeError(`Invalid receipt at ${path}.receipts[${index}]`);
    assertExactKeys(receipt, ["status", "at", "data"], `${path}.receipts[${index}]`);
    if (!OPERATION_STATUSES.includes(receipt.status) || receipt.status === "pending") {
      throw new TypeError(`Invalid receipt status at ${path}.receipts[${index}]`);
    }
    assertTimestamp(receipt.at, `${path}.receipts[${index}].at`);
    if (receipt.at > state.updatedAt) throw new TypeError(`Receipt timestamp exceeds updatedAt at ${path}`);
    if (!isPlainObject(receipt.data)) throw new TypeError(`Invalid receipt data at ${path}.receipts[${index}]`);
  }
  if (operation.error !== null && typeof operation.error !== "string") {
    throw new TypeError(`Invalid error at ${path}`);
  }
  if (operation.status === "failed" && !operation.error) {
    throw new TypeError(`Failed operation requires an error at ${path}`);
  }
  if (operation.status !== "failed" && operation.error !== null) {
    throw new TypeError(`Only failed operations may have an error at ${path}`);
  }
}

function assertState(state) {
  assertJsonValue(state);
  assertNoSecrets(state);
  if (!isPlainObject(state)) throw new TypeError("State must be an object");
  assertExactKeys(state, [
    "schema", "version", "createdAt", "updatedAt", "includeMailbox", "context", "operations",
  ], "$");
  if (state.schema !== STATE_SCHEMA) throw new TypeError("Unsupported state schema");
  if (state.version !== STATE_VERSION) throw new TypeError("Unsupported state version");
  assertTimestamp(state.createdAt, "$.createdAt");
  assertTimestamp(state.updatedAt, "$.updatedAt");
  if (state.updatedAt < state.createdAt) throw new TypeError("updatedAt precedes createdAt");
  if (typeof state.includeMailbox !== "boolean") throw new TypeError("Invalid includeMailbox flag");
  if (!isPlainObject(state.context)) throw new TypeError("Invalid state context");
  if (!isPlainObject(state.operations)) throw new TypeError("Invalid operations object");
  assertExactKeys(state.operations, OPERATION_ORDER, "$.operations");
  for (const name of OPERATION_ORDER) {
    if (!Object.prototype.hasOwnProperty.call(state.operations, name)) {
      throw new TypeError(`Missing operation: ${name}`);
    }
    assertOperation(state.operations[name], name, state);
  }
  for (let index = 1; index < OPERATION_ORDER.length; index += 1) {
    const current = state.operations[OPERATION_ORDER[index]];
    if (!current.enabled || !["published", "verified"].includes(current.status)) continue;
    const previous = state.operations[OPERATION_ORDER[index - 1]];
    if (!previous.enabled || previous.status !== "verified") {
      throw new TypeError(`Operation order violation at ${OPERATION_ORDER[index]}`);
    }
  }
  return state;
}

function canTransition(fromStatus, toStatus) {
  return Boolean(ALLOWED_TRANSITIONS[fromStatus]?.includes(toStatus));
}

function previousEnabledOperation(state, name) {
  const index = OPERATION_ORDER.indexOf(name);
  for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
    const candidate = state.operations[OPERATION_ORDER[cursor]];
    if (candidate.enabled) return candidate;
  }
  return null;
}

function transitionOperation(state, name, toStatus, options = {}) {
  assertState(state);
  if (!OPERATION_ORDER.includes(name)) throw new TypeError(`Unknown operation: ${name}`);
  if (!isPlainObject(options)) throw new TypeError("Transition options must be an object");
  const current = state.operations[name];
  if (!current.enabled) throw new Error(`Operation is disabled: ${name}`);
  if (!canTransition(current.status, toStatus)) {
    throw new Error(`Invalid transition for ${name}: ${current.status} -> ${toStatus}`);
  }
  if (["published", "verified"].includes(toStatus)) {
    const previous = previousEnabledOperation(state, name);
    if (previous && previous.status !== "verified") {
      throw new Error(`Previous operation must be verified before ${name}`);
    }
  }
  if (["published", "verified"].includes(toStatus) && !isPlainObject(options.receipt)) {
    throw new TypeError(`${toStatus} transition requires a receipt object`);
  }
  if (toStatus === "failed" && (typeof options.error !== "string" || !options.error.trim())) {
    throw new TypeError("Failed transition requires an error message");
  }

  const at = isoTimestamp(options.at);
  if (at < state.updatedAt) throw new TypeError("Transition timestamp precedes state.updatedAt");
  const next = cloneJson(state);
  const operation = next.operations[name];
  operation.status = toStatus;
  operation.statusAt = at;
  operation.timestamps[toStatus] = at;
  operation.error = toStatus === "failed" ? options.error.trim() : null;
  if (options.receipt !== undefined) {
    if (!isPlainObject(options.receipt)) throw new TypeError("Receipt must be an object");
    operation.receipts.push({
      status: toStatus,
      at,
      data: cloneJson(options.receipt),
    });
  }
  next.updatedAt = at;
  assertState(next);
  return next;
}

function nextOperation(state) {
  assertState(state);
  for (const name of OPERATION_ORDER) {
    const operation = state.operations[name];
    if (operation.enabled && operation.status !== "verified") return name;
  }
  return null;
}

function serializeState(state, space = 2) {
  assertState(state);
  const indentation = Number.isInteger(space) && space >= 0 && space <= 10 ? space : 2;
  return JSON.stringify(state, null, indentation);
}

function parseState(serialized) {
  if (typeof serialized !== "string") throw new TypeError("Serialized state must be a string");
  let parsed;
  try {
    parsed = JSON.parse(serialized);
  } catch (error) {
    throw new TypeError(`Invalid state JSON: ${error.message}`);
  }
  assertState(parsed);
  return cloneJson(parsed);
}

module.exports = {
  ALLOWED_TRANSITIONS,
  OPERATION_ORDER,
  OPERATION_STATUSES,
  STATE_SCHEMA,
  STATE_VERSION,
  assertNoSecrets,
  assertState,
  canTransition,
  createState,
  isSignatureBearingWriteUrl,
  nextOperation,
  parseState,
  serializeState,
  transitionOperation,
};
