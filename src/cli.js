#!/usr/bin/env node
"use strict";

const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline/promises");
const { stdin, stdout, stderr } = require("node:process");
const { TechnocoreClient } = require("./client");
const {
  deserializeKeystore,
  generateIdentity,
  serializeKeystore,
} = require("./identity");
const { assertPlanContext, prepareKit } = require("./kit");
const { SafePublisher } = require("./publisher");
const { serializePublicProof } = require("./proof");
const { TECHNOCORE_URL } = require("./protocol");
const {
  OPERATION_ORDER,
  nextOperation,
  parseState,
  transitionOperation,
} = require("./state");
const { readJson, writeJsonAtomic, writeTextAtomic } = require("./storage");
const { auditState } = require("./verifier");

const BOOLEAN_FLAGS = new Set(["force", "help", "json", "mailbox", "offline", "retry", "yes"]);
const COMMON_PRIVATE_FLAGS = ["data-dir", "identity", "passphrase-file", "state"];
const ALLOWED_FLAGS = Object.freeze({
  init: new Set(["data-dir", "identity", "passphrase-file"]),
  prepare: new Set([...COMMON_PRIVATE_FLAGS, "proof-dir", "agent", "type", "summary", "url", "x", "mailbox", "base-url", "force"]),
  publish: new Set([...COMMON_PRIVATE_FLAGS, "proof-dir", "yes", "retry"]),
  resume: new Set([...COMMON_PRIVATE_FLAGS, "proof-dir", "yes", "retry"]),
  verify: new Set(["data-dir", "state", "proof-dir", "json"]),
  status: new Set(["data-dir", "state"]),
  proof: new Set(["data-dir", "state", "proof-dir", "offline"]),
  help: new Set(["help"]),
});

function parseArgs(argv) {
  const parsed = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      parsed._.push(token);
      continue;
    }
    const equal = token.indexOf("=");
    if (equal > 2) {
      const key = token.slice(2, equal);
      if (BOOLEAN_FLAGS.has(key)) throw new Error(`--${key} is a boolean flag and does not accept a value.`);
      if (Object.prototype.hasOwnProperty.call(parsed, key)) throw new Error(`Duplicate option: --${key}`);
      parsed[key] = token.slice(equal + 1);
      continue;
    }
    const key = token.slice(2);
    if (Object.prototype.hasOwnProperty.call(parsed, key)) throw new Error(`Duplicate option: --${key}`);
    const next = argv[index + 1];
    if (BOOLEAN_FLAGS.has(key)) {
      if (next !== undefined && !next.startsWith("--")) {
        throw new Error(`--${key} is a boolean flag and does not accept a value.`);
      }
      parsed[key] = true;
    } else if (next !== undefined && !next.startsWith("--")) {
      parsed[key] = next;
      index += 1;
    } else {
      parsed[key] = true;
    }
  }
  return parsed;
}

function validateArgs(command, args) {
  const allowed = ALLOWED_FLAGS[command];
  if (!allowed) throw new Error(`Unknown command: ${command}`);
  if (args._.length !== 1) throw new Error(`Unexpected positional arguments for ${command}.`);
  for (const [key, value] of Object.entries(args)) {
    if (key === "_") continue;
    if (!allowed.has(key)) throw new Error(`Option --${key} is not valid for ${command}.`);
    if (!BOOLEAN_FLAGS.has(key) && value === true) throw new Error(`Option --${key} requires a value.`);
  }
}

function locations(args) {
  const dataDirectory = path.resolve(args["data-dir"] || path.join(os.homedir(), ".technocore-safeproof"));
  return {
    dataDirectory,
    identityPath: path.resolve(args.identity || path.join(dataDirectory, "identity.json")),
    statePath: path.resolve(args.state || path.join(dataDirectory, "state.json")),
    proofDirectory: path.resolve(args["proof-dir"] || path.join(process.cwd(), "proofs")),
  };
}

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function ask(question, defaultValue = "") {
  const terminal = readline.createInterface({ input: stdin, output: stdout });
  try {
    const suffix = defaultValue ? ` [${defaultValue}]` : "";
    const answer = await terminal.question(`${question}${suffix}: `);
    return answer.trim() || defaultValue;
  } finally {
    terminal.close();
  }
}

async function confirm(question) {
  const answer = (await ask(`${question} (y/N)`)).toLowerCase();
  return answer === "y" || answer === "yes" || answer === "e" || answer === "evet";
}

async function askSecret(question) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== "function") {
    throw new Error("A TTY is required for a hidden passphrase. Use --passphrase-file in non-interactive environments.");
  }
  return new Promise((resolve, reject) => {
    let value = "";
    const restore = () => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
    };
    const finish = () => {
      restore();
      stderr.write("\n");
      resolve(value);
    };
    const onData = (chunk) => {
      for (const character of String(chunk)) {
        if (character === "\u0003") {
          restore();
          stderr.write("\n");
          reject(new Error("Cancelled."));
          return;
        }
        if (character === "\r" || character === "\n") {
          finish();
          return;
        }
        if (character === "\u007f" || character === "\b") {
          if (value) {
            value = Array.from(value).slice(0, -1).join("");
            stderr.write("\b \b");
          }
          continue;
        }
        value += character;
        stderr.write("*");
      }
    };
    stderr.write(`${question}: `);
    stdin.setEncoding("utf8");
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}

async function passphraseFrom(args, options = {}) {
  if (args["passphrase-file"]) {
    const value = (await fs.readFile(path.resolve(args["passphrase-file"]), "utf8")).replace(/\r?\n$/, "");
    if (!value) throw new Error("Passphrase file is empty.");
    if (options.create && value.length < 12) throw new Error("New passphrase must be at least 12 characters.");
    return value;
  }
  const value = await askSecret(options.create ? "Create identity passphrase" : "Identity passphrase");
  if (!value) throw new Error("Passphrase cannot be empty.");
  if (options.create) {
    if (value.length < 12) throw new Error("New passphrase must be at least 12 characters.");
    const repeated = await askSecret("Repeat passphrase");
    if (value !== repeated) throw new Error("Passphrases do not match.");
  }
  return value;
}

async function loadIdentity(identityPath, args) {
  if (!(await exists(identityPath))) throw new Error(`Identity not found: ${identityPath}`);
  const passphrase = await passphraseFrom(args);
  try {
    return deserializeKeystore(await fs.readFile(identityPath, "utf8"), passphrase);
  } finally {
    // JavaScript strings cannot be reliably zeroed; keep the passphrase scoped to this function.
  }
}

async function loadState(statePath) {
  if (!(await exists(statePath))) throw new Error(`Prepared state not found: ${statePath}`);
  return assertPlanContext(parseState(JSON.stringify(await readJson(statePath))));
}

function printStatus(state) {
  stdout.write(`\nDID: ${state.context.identity.did}\n`);
  stdout.write(`Contribution: ${state.context.contribution.contributionSummary}\n\n`);
  for (const name of OPERATION_ORDER) {
    const operation = state.operations[name];
    const status = operation.enabled ? operation.status : "skipped";
    stdout.write(`${name.padEnd(14)} ${status}${operation.enabled ? `  ${operation.statusAt}` : ""}\n`);
    if (operation.error) stdout.write(`${"".padEnd(14)} error: ${operation.error}\n`);
    const receipt = operation.receipts.at(-1);
    if (receipt) {
      const summary = [
        receipt.data.outcome,
        receipt.data.httpStatus ? `HTTP ${receipt.data.httpStatus}` : "",
        receipt.data.retryAfter ? `retry-after ${receipt.data.retryAfter}` : "",
      ].filter(Boolean).join(", ");
      if (summary) stdout.write(`${"".padEnd(14)} last receipt: ${summary}\n`);
    }
  }
  const next = nextOperation(state);
  if (next) stdout.write(`\nNext: ${next} (${state.operations[next].status})\n`);
  if (next && state.operations[next].status === "unknown") {
    stdout.write("Action: resume performs read-back first; --retry may create a duplicate signed message.\n");
  } else if (next && state.operations[next].status === "published") {
    stdout.write("Action: resume is verify-only; the acknowledged write will not be resent.\n");
  } else if (next && state.operations[next].status === "failed") {
    stdout.write("Action: inspect the error; resume --retry is an explicit new write attempt.\n");
  }
  stdout.write("\n");
}

function printPublishPreview(state) {
  const rooms = ["lobby", "announcement", ...(state.includeMailbox ? ["mailbox"] : [])]
    .map((name) => state.context.messages[name].room)
    .join(", ");
  stdout.write([
    "Publish preview:",
    `  Origin: ${state.context.baseUrl}${state.context.baseUrl === TECHNOCORE_URL ? "" : " (custom)"}`,
    `  DID: ${state.context.identity.did}`,
    `  Contribution: ${state.context.contribution.contributionSummary}`,
    `  Contribution record: ${state.context.records.contribution.path}`,
    `  Profile record: ${state.context.records.profile.path}`,
    `  Public rooms: ${rooms}`,
    state.includeMailbox ? `  Public mailbox: ${state.context.contribution.mailbox}` : "  Public mailbox: disabled",
    "",
  ].join("\n"));
}

async function writeProofFiles(state, directory, options = {}) {
  const exported = serializePublicProof(state, options);
  const stem = `technocore-safeproof-${state.context.identity.fingerprint}`;
  const jsonPath = path.join(directory, `${stem}.json`);
  const markdownPath = path.join(directory, `${stem}.md`);
  await writeTextAtomic(jsonPath, exported.json, { mode: 0o644, directoryMode: 0o755 });
  await writeTextAtomic(markdownPath, exported.markdown, { mode: 0o644, directoryMode: 0o755 });
  return { jsonPath, markdownPath, status: exported.proof.status };
}

async function initCommand(args) {
  const paths = locations(args);
  if (await exists(paths.identityPath)) {
    throw new Error(`Identity already exists: ${paths.identityPath}`);
  }
  const passphrase = await passphraseFrom(args, { create: true });
  const identity = generateIdentity();
  await writeTextAtomic(paths.identityPath, serializeKeystore(identity, passphrase), {
    mode: 0o600,
    directoryMode: 0o700,
  });
  stdout.write(`\nIdentity created locally.\nDID: ${identity.did}\nFingerprint: ${identity.fingerprint}\n`);
  stdout.write(`Encrypted keystore: ${paths.identityPath}\nKeep this file and its passphrase private.\n`);
  stdout.write("Back up the encrypted keystore and passphrase separately; never use a wallet seed or wallet key.\n");
}

async function prepareCommand(args) {
  const paths = locations(args);
  if (await exists(paths.statePath)) {
    const existing = await loadState(paths.statePath);
    if (!args.force) {
      throw new Error(`Prepared state already exists: ${paths.statePath} (use --force only for an unpublished plan)`);
    }
    const progressed = OPERATION_ORDER.some((name) => {
      const operation = existing.operations[name];
      return operation.enabled && (operation.status !== "prepared" || operation.receipts.length > 0);
    });
    if (progressed) throw new Error("Refusing to replace a state that contains publish history.");
  }
  const identity = await loadIdentity(paths.identityPath, args);
  const input = {
    agentName: args.agent || await ask("Agent name"),
    contributionType: args.type || await ask("Contribution type", "tool"),
    contributionSummary: args.summary || await ask("Contribution summary"),
    guideUrl: args.url !== undefined ? args.url : await ask("Contribution URL (optional)"),
    xHandle: args.x !== undefined ? args.x : await ask("X handle (optional)"),
    includeMailbox: args.mailbox === true,
    baseUrl: args["base-url"],
  };
  const state = prepareKit(identity, input);
  await writeJsonAtomic(paths.statePath, state, { mode: 0o600 });
  const proof = await writeProofFiles(state, paths.proofDirectory);
  stdout.write(`\nSafeProof plan prepared without publishing anything.\nState: ${paths.statePath}\n`);
  stdout.write(`Draft proof: ${proof.markdownPath}\n`);
  printStatus(state);
}

async function statusCommand(args) {
  printStatus(await loadState(locations(args).statePath));
}

async function proofCommand(args) {
  const paths = locations(args);
  const state = await loadState(paths.statePath);
  const audit = args.offline
    ? null
    : await auditState(state, new TechnocoreClient({ baseUrl: state.context.baseUrl }));
  const result = await writeProofFiles(state, paths.proofDirectory, { audit });
  stdout.write(`Proof status: ${result.status}\nJSON: ${result.jsonPath}\nMarkdown: ${result.markdownPath}\n`);
  if (!audit) stdout.write("Offline artifact: current Technocore state was not checked.\n");
  if (audit && !audit.ok) process.exitCode = 2;
}

async function publishCommand(args) {
  const paths = locations(args);
  let state = await loadState(paths.statePath);
  printStatus(state);
  printPublishPreview(state);
  if (!args.yes && !(await confirm("Publish the next safe sequence to Technocore?"))) {
    stdout.write("No changes were published.\n");
    return;
  }
  const identity = await loadIdentity(paths.identityPath, args);
  const client = new TechnocoreClient({ baseUrl: state.context.baseUrl });
  await client.health();

  const publisher = new SafePublisher(client, {
    onState: async (next) => writeJsonAtomic(paths.statePath, next, { mode: 0o600 }),
  });

  let current = nextOperation(state);
  if (current && state.operations[current].status === "unknown") {
    state = await publisher.publishNext(state, identity);
    await writeJsonAtomic(paths.statePath, state, { mode: 0o600 });
    current = nextOperation(state);
  }
  if (current && ["unknown", "failed"].includes(state.operations[current].status)) {
    if (!args.retry) {
      throw new Error(`${current} is ${state.operations[current].status}; read-back did not recover it. Inspect status, then use resume --retry only if duplicate risk is acceptable.`);
    }
    state = transitionOperation(state, current, "prepared");
    await writeJsonAtomic(paths.statePath, state, { mode: 0o600 });
  }

  state = await publisher.publishAll(state, identity);
  await writeJsonAtomic(paths.statePath, state, { mode: 0o600 });
  const audit = await auditState(state, client);
  const proof = await writeProofFiles(state, paths.proofDirectory, { audit });
  printStatus(state);
  stdout.write(`Proof status: ${proof.status}\nProof: ${proof.markdownPath}\n`);
  current = nextOperation(state);
  if (current) stdout.write(`Stopped at ${current}; no later operations were sent.\n`);
  if (!audit.ok) process.exitCode = 2;
}

async function verifyCommand(args) {
  const paths = locations(args);
  const state = await loadState(paths.statePath);
  const client = new TechnocoreClient({ baseUrl: state.context.baseUrl });
  const audit = await auditState(state, client);
  const proof = await writeProofFiles(state, paths.proofDirectory, { audit });
  if (args.json) {
    stdout.write(`${JSON.stringify({ audit, proof }, null, 2)}\n`);
    if (!audit.ok) process.exitCode = 2;
    return;
  }
  for (const name of OPERATION_ORDER) {
    if (!state.operations[name].enabled || !audit.results[name]) continue;
    const result = audit.results[name];
    stdout.write(`${name.padEnd(14)} ${result.ok ? "verified" : "not verified"}${result.error ? ` — ${result.error}` : ""}\n`);
    if (!result.ok && result.expectedSha256) {
      stdout.write(`${"".padEnd(14)} expected ${result.expectedSha256}; actual ${result.actualSha256 || "missing"}\n`);
    }
  }
  stdout.write(`\nAudit: ${audit.ok ? "verified" : "incomplete or changed"}\n`);
  stdout.write(`Audit-bound proof: ${proof.markdownPath}\n`);
  if (!audit.ok) process.exitCode = 2;
}

function help() {
  stdout.write([
    "Technocore SafeProof CLI",
    "",
    "Usage:",
    "  safeproof init [--passphrase-file PATH]",
    "  safeproof prepare --agent NAME --type tool --summary TEXT [--url URL] [--x HANDLE] [--mailbox]",
    "  safeproof publish [--yes]",
    "  safeproof resume [--retry] [--yes]",
    "  safeproof verify",
    "  safeproof status",
    "  safeproof proof",
    "",
    "Common paths:",
    "  --data-dir PATH   Local encrypted identity and operation state",
    "  --identity PATH   Encrypted keystore override",
    "  --state PATH      Operation state override",
    "  --proof-dir PATH  Public proof output directory",
    "  --passphrase-file PATH  Non-interactive secret input (keep it private)",
    "",
    "Safety options:",
    "  --base-url URL   Signed custom HTTPS origin during prepare",
    "  --force          Replace only an entirely unpublished prepared state",
    "  --retry          Explicitly retry failed/unknown work after read-back; duplicate risk exists",
    "  --offline        Export a non-verified historical artifact without live audit",
    "  --json           Machine-readable verify result",
    "  --mailbox        Create an optional public mailbox",
    "  --yes            Bare boolean flag; bypass the publish confirmation",
    "",
    "Proof exports are verified only after a fresh successful live audit.",
    "Boolean flags never accept values such as --yes=false.",
    "",
    "Private keys never appear in proof files or Technocore requests.",
    "",
  ].join("\n"));
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const command = args.help ? "help" : (args._[0] || "help");
  if (["help", "--help", "-h"].includes(command)) return help();
  validateArgs(command, args);
  if (command === "init") return initCommand(args);
  if (command === "prepare") return prepareCommand(args);
  if (command === "status") return statusCommand(args);
  if (command === "proof") return proofCommand(args);
  if (command === "publish" || command === "resume") return publishCommand(args);
  if (command === "verify") return verifyCommand(args);
  throw new Error(`Unknown command: ${command}`);
}

if (require.main === module) {
  main().catch((error) => {
    stderr.write(`SafeProof error: ${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  locations,
  main,
  parseArgs,
  validateArgs,
};
