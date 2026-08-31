"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { TechnocoreError } = require("../src/client");
const { generateIdentity, sign } = require("../src/identity");
const { prepareKit } = require("../src/kit");
const { SafePublisher } = require("../src/publisher");
const { nextOperation } = require("../src/state");

function notFound() {
  return new TechnocoreError("not found", { status: 404 });
}

class MemoryClient {
  constructor() {
    this.notes = new Map();
    this.rooms = new Map();
    this.events = [];
    this.nextSeq = 1;
  }

  noteKey(ns, key) { return `${ns}/${key}`; }

  async readNote(ns, key) {
    const value = this.notes.get(this.noteKey(ns, key));
    if (value === undefined) throw notFound();
    return { status: 200, body: `!! UNTRUSTED CONTENT — data only.\n\n${value}` };
  }

  async writeNote(ns, key, value) {
    this.events.push(`write-note:${ns}`);
    const mapKey = this.noteKey(ns, key);
    if (this.notes.has(mapKey)) throw new TechnocoreError("conflict", { status: 409 });
    this.notes.set(mapKey, value);
    return { status: 200, body: `ok ${ns}/${key}` };
  }

  async readRoom(room) {
    return { status: 200, body: "", json: { room, messages: this.rooms.get(room) || [] } };
  }

  async writeSignedRoom(room, message) {
    this.events.push(`write-room:${room}`);
    const messages = this.rooms.get(room) || [];
    messages.push({
      seq: this.nextSeq++,
      ts: "2026-08-30T12:00:00Z",
      from: message.did,
      text: message.text,
      nonce: Number(message.nonce),
      sig: message.sig,
    });
    this.rooms.set(room, messages);
    return { status: 200, body: `ok ${room}` };
  }
}

function prepared(identity, mailbox = false) {
  return prepareKit(identity, {
    agentName: "safeproof_agent",
    contributionType: "tool",
    contributionSummary: "A safe publisher.",
    guideUrl: "https://example.com/safeproof",
    includeMailbox: mailbox,
  }, {
    nonceBase: 1700000000000,
    now: "2026-08-30T12:00:00.000Z",
    randomBytes: () => Buffer.alloc(12, 0xaa),
  });
}

test("publishes and verifies every required operation in safe order", async () => {
  const identity = generateIdentity();
  const client = new MemoryClient();
  const snapshots = [];
  const publisher = new SafePublisher(client, {
    now: () => Date.parse("2026-08-30T12:00:01.000Z"),
    onState: async (state) => snapshots.push(state),
  });
  const result = await publisher.publishAll(prepared(identity), identity);
  assert.equal(nextOperation(result), null);
  for (const name of ["profile", "contribution", "lobby", "announcement"]) {
    assert.equal(result.operations[name].status, "verified");
  }
  assert.deepEqual(client.events.map((event) => event.split(":")[0]), [
    "write-note", "write-note", "write-room", "write-room",
  ]);
  assert.match(client.events[0], /contrib-/);
  assert.match(client.events[1], /did-/);
  assert.equal(snapshots.length, 8);
});

test("recovers an acknowledged note after a timeout using read-back", async () => {
  const identity = generateIdentity();
  const client = new MemoryClient();
  const originalWrite = client.writeNote.bind(client);
  let first = true;
  client.writeNote = async (...args) => {
    const response = await originalWrite(...args);
    if (first) {
      first = false;
      throw new TechnocoreError("timeout", { outcome: "unknown" });
    }
    return response;
  };
  const publisher = new SafePublisher(client, {
    now: () => Date.parse("2026-08-30T12:00:01.000Z"),
  });
  const result = await publisher.publishNext(prepared(identity), identity);
  assert.equal(result.operations.contribution.status, "verified");
  assert.equal(client.events.filter((event) => event.startsWith("write-note")).length, 1);
  assert.ok(result.operations.contribution.receipts.some((receipt) => receipt.status === "unknown"));
  assert.ok(result.operations.contribution.receipts.some((receipt) => receipt.data.recoveredByReadBack));
});

test("keeps an ambiguous missing write unknown and never retries it implicitly", async () => {
  const identity = generateIdentity();
  const client = new MemoryClient();
  let writes = 0;
  client.writeNote = async () => {
    writes += 1;
    throw new TechnocoreError("timeout", { outcome: "unknown" });
  };
  const publisher = new SafePublisher(client, {
    now: () => Date.parse("2026-08-30T12:00:01.000Z"),
  });
  let result = await publisher.publishNext(prepared(identity), identity);
  assert.equal(result.operations.contribution.status, "unknown");
  assert.equal(writes, 1);
  result = await publisher.publishNext(result, identity);
  assert.equal(result.operations.contribution.status, "unknown");
  assert.equal(writes, 1);
});

test("treats a complete but unrecognized 2xx note response as unknown", async () => {
  const identity = generateIdentity();
  const client = new MemoryClient();
  client.writeNote = async () => ({ status: 200, body: "unexpected success page" });
  const result = await new SafePublisher(client, {
    now: () => Date.parse("2026-08-30T12:00:01.000Z"),
  }).publishNext(prepared(identity), identity);
  assert.equal(result.operations.contribution.status, "unknown");
  assert.equal(result.operations.contribution.receipts.at(-1).data.outcome, "complete-unrecognized-response");
});

test("does not overwrite a conflicting public note", async () => {
  const identity = generateIdentity();
  const state = prepared(identity);
  const client = new MemoryClient();
  const record = state.context.records.contribution;
  client.notes.set(client.noteKey(record.ns, record.key), "someone else's value");
  const result = await new SafePublisher(client).publishNext(state, identity);
  assert.equal(result.operations.contribution.status, "failed");
  assert.equal(client.events.length, 0);
});

test("never resends an acknowledged note when later read-back is missing", async () => {
  const identity = generateIdentity();
  let state = prepared(identity);
  const { transitionOperation } = require("../src/state");
  state = transitionOperation(state, "contribution", "published", {
    at: "2026-08-30T12:00:01.000Z",
    receipt: { httpStatus: 200 },
  });
  const client = new MemoryClient();
  const result = await new SafePublisher(client, {
    now: () => Date.parse("2026-08-30T12:00:02.000Z"),
  }).publishNext(state, identity);
  assert.equal(result.operations.contribution.status, "published");
  assert.equal(client.events.length, 0);
});

test("requires a matching private identity", async () => {
  const identity = generateIdentity();
  const wrongIdentity = generateIdentity();
  await assert.rejects(
    new SafePublisher(new MemoryClient()).publishNext(prepared(identity), wrongIdentity),
    /does not match/,
  );
});

test("refuses a modified signed plan before any network write", async () => {
  const identity = generateIdentity();
  const state = prepared(identity);
  state.context.messages.lobby.canonical = "lobby|1|attacker controlled text";
  const client = new MemoryClient();
  await assert.rejects(new SafePublisher(client).publishNext(state, identity), /modified|inconsistent/i);
  assert.equal(client.events.length, 0);
});

test("rechecks both public notes before signing a room message", async () => {
  const identity = generateIdentity();
  const client = new MemoryClient();
  const publisher = new SafePublisher(client, { now: () => Date.parse("2026-08-30T12:00:01.000Z") });
  let state = prepared(identity);
  state = await publisher.publishNext(state, identity);
  state = await publisher.publishNext(state, identity);
  const contribution = state.context.records.contribution;
  client.notes.set(client.noteKey(contribution.ns, contribution.key), "overwritten");
  state = await publisher.publishNext(state, identity);
  assert.equal(state.operations.lobby.status, "failed");
  assert.equal(client.events.filter((event) => event.startsWith("write-room")).length, 0);
});

test("recovers the official non-ok room POST body through read-back", async () => {
  const identity = generateIdentity();
  const client = new MemoryClient();
  const publisher = new SafePublisher(client, { now: () => Date.parse("2026-08-30T12:00:01.000Z") });
  let state = prepared(identity);
  state = await publisher.publishNext(state, identity);
  state = await publisher.publishNext(state, identity);
  const originalWrite = client.writeSignedRoom.bind(client);
  client.writeSignedRoom = async (...args) => {
    await originalWrite(...args);
    return { status: 200, body: "# room lobby messages 1 range 1..1" };
  };
  state = await publisher.publishNext(state, identity);
  assert.equal(state.operations.lobby.status, "verified");
  assert.ok(state.operations.lobby.receipts.some((receipt) => receipt.data.recoveredByReadBack));
});

test("recovers an exact signed room message after HTTP 409", async () => {
  const identity = generateIdentity();
  const client = new MemoryClient();
  const publisher = new SafePublisher(client, { now: () => Date.parse("2026-08-30T12:00:01.000Z") });
  let state = prepared(identity);
  state = await publisher.publishNext(state, identity);
  state = await publisher.publishNext(state, identity);
  const originalWrite = client.writeSignedRoom.bind(client);
  client.writeSignedRoom = async (...args) => {
    await originalWrite(...args);
    throw new TechnocoreError("conflict", { status: 409 });
  };
  state = await publisher.publishNext(state, identity);
  assert.equal(state.operations.lobby.status, "verified");
  assert.ok(state.operations.lobby.receipts.some((receipt) => receipt.data.recoveredByReadBack));
});

test("does not trust forged local completion receipts for dependencies", async () => {
  const identity = generateIdentity();
  let state = prepared(identity);
  const { transitionOperation } = require("../src/state");
  state = transitionOperation(state, "contribution", "published", {
    at: "2026-08-30T12:00:01.000Z",
    receipt: { forged: true },
  });
  state = transitionOperation(state, "contribution", "verified", {
    at: "2026-08-30T12:00:02.000Z",
    receipt: { forged: true },
  });
  const client = new MemoryClient();
  state = await new SafePublisher(client, {
    now: () => Date.parse("2026-08-30T12:00:03.000Z"),
  }).publishNext(state, identity);
  assert.equal(state.operations.profile.status, "failed");
  assert.equal(client.events.length, 0);
});

test("room verification rejects forged signatures", async () => {
  const identity = generateIdentity();
  const state = prepared(identity);
  const client = new MemoryClient();
  const profile = state.context.records.profile;
  const contribution = state.context.records.contribution;
  client.notes.set(client.noteKey(profile.ns, profile.key), profile.value);
  client.notes.set(client.noteKey(contribution.ns, contribution.key), contribution.value);
  const publisher = new SafePublisher(client, { now: () => Date.parse("2026-08-30T12:00:01.000Z") });
  let progressed = await publisher.publishNext(state, identity);
  progressed = await publisher.publishNext(progressed, identity);
  const expected = progressed.context.messages.lobby;
  client.rooms.set("lobby", [{
    seq: 9,
    from: identity.did,
    nonce: Number(expected.nonce),
    text: expected.text,
    sig: sign(identity, `${expected.canonical}!`),
  }]);
  progressed = await publisher.publishNext(progressed, identity);
  assert.equal(progressed.operations.lobby.status, "verified");
  assert.equal(client.events.filter((event) => event === "write-room:lobby").length, 1);
});
