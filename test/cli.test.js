"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { generateIdentity } = require("../src/identity");
const { prepareKit } = require("../src/kit");
const { main, parseArgs, validateArgs } = require("../src/cli");
const { transitionOperation } = require("../src/state");

test("parses commands, flags, booleans, and equals syntax", () => {
  assert.deepEqual(parseArgs([
    "prepare", "--agent", "safeproof_agent", "--mailbox", "--type=tool",
  ]), {
    _: ["prepare"],
    agent: "safeproof_agent",
    mailbox: true,
    type: "tool",
  });
});

test("rejects valued, duplicate, and unknown approval flags", () => {
  assert.throws(() => parseArgs(["publish", "--yes=false"]), /boolean flag/);
  assert.throws(() => parseArgs(["publish", "--yes", "no"]), /does not accept/);
  assert.throws(() => parseArgs(["publish", "--yes", "--yes"]), /Duplicate/);
  assert.throws(() => validateArgs("publish", parseArgs(["publish", "--mailbox"])), /not valid/);
});

test("runs the local init and prepare flow without publishing", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "safeproof-cli-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const dataDirectory = path.join(directory, "data");
  const proofDirectory = path.join(directory, "proofs");
  const passphrasePath = path.join(directory, "passphrase.txt");
  await fs.writeFile(passphrasePath, "a-local-test-passphrase\n", { mode: 0o600 });

  const init = spawnSync(process.execPath, [
    "src/cli.js", "init",
    "--data-dir", dataDirectory,
    "--passphrase-file", passphrasePath,
  ], { cwd: path.resolve(__dirname, ".."), encoding: "utf8" });
  assert.equal(init.status, 0, init.stderr);
  assert.match(init.stdout, /Identity created locally/);

  const prepare = spawnSync(process.execPath, [
    "src/cli.js", "prepare",
    "--data-dir", dataDirectory,
    "--proof-dir", proofDirectory,
    "--passphrase-file", passphrasePath,
    "--agent", "safeproof_agent",
    "--type", "tool",
    "--summary", "A safe local publisher.",
    "--url", "https://example.com/repo",
    "--x=",
  ], { cwd: path.resolve(__dirname, ".."), encoding: "utf8" });
  assert.equal(prepare.status, 0, prepare.stderr);
  assert.match(prepare.stdout, /without publishing anything/);

  const identity = await fs.readFile(path.join(dataDirectory, "identity.json"), "utf8");
  const state = JSON.parse(await fs.readFile(path.join(dataDirectory, "state.json"), "utf8"));
  const proofFiles = await fs.readdir(proofDirectory);
  assert.equal(identity.includes('"d"'), false);
  assert.equal(JSON.stringify(state).includes("privateKey"), false);
  assert.equal(state.operations.profile.status, "prepared");
  assert.equal(proofFiles.some((name) => name.endsWith(".md")), true);
  assert.equal(proofFiles.some((name) => name.endsWith(".json")), true);
});

test("refuses --force when state contains publish history", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "safeproof-cli-force-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const statePath = path.join(directory, "state.json");
  let state = prepareKit(generateIdentity(), {
    agentName: "safeproof_agent",
    contributionType: "tool",
    contributionSummary: "A test contribution.",
  }, { nonceBase: 1700000000000, now: "2026-08-30T12:00:00.000Z" });
  state = transitionOperation(state, "contribution", "published", {
    at: "2026-08-30T12:00:01.000Z",
    receipt: { httpStatus: 200 },
  });
  await fs.writeFile(statePath, `${JSON.stringify(state)}\n`);
  await assert.rejects(main([
    "prepare", "--state", statePath, "--force",
    "--agent", "safeproof_agent", "--type", "tool", "--summary", "replacement",
  ]), /Refusing to replace/);
});

test("online proof exits 2 when the live audit fails", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "safeproof-cli-proof-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const statePath = path.join(directory, "state.json");
  const proofDirectory = path.join(directory, "proofs");
  const state = prepareKit(generateIdentity(), {
    agentName: "safeproof_agent",
    contributionType: "tool",
    contributionSummary: "A test contribution.",
  }, { nonceBase: 1700000000000, now: "2026-08-30T12:00:00.000Z" });
  await fs.writeFile(statePath, `${JSON.stringify(state)}\n`);
  const originalFetch = globalThis.fetch;
  const originalExitCode = process.exitCode;
  globalThis.fetch = async () => new Response("not found", { status: 404 });
  try {
    process.exitCode = undefined;
    await main(["proof", "--state", statePath, "--proof-dir", proofDirectory]);
    assert.equal(process.exitCode, 2);
  } finally {
    globalThis.fetch = originalFetch;
    process.exitCode = originalExitCode;
  }
});
