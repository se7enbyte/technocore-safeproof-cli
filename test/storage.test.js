"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { readJson, writeJsonAtomic, writeTextAtomic } = require("../src/storage");

test("writes JSON and text atomically", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "safeproof-storage-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const jsonPath = path.join(directory, "private", "state.json");
  const textPath = path.join(directory, "public", "proof.md");
  await writeJsonAtomic(jsonPath, { ok: true });
  await writeTextAtomic(textPath, "proof\n");
  assert.deepEqual(await readJson(jsonPath), { ok: true });
  assert.equal(await fs.readFile(textPath, "utf8"), "proof\n");
  if (process.platform !== "win32") {
    const stat = await fs.stat(jsonPath);
    assert.equal(stat.mode & 0o777, 0o600);
  }
});

test("reports invalid JSON without returning partial state", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "safeproof-storage-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "bad.json");
  await fs.writeFile(filePath, "{");
  await assert.rejects(readJson(filePath), /Invalid JSON/);
});

test("never changes permissions of an existing parent directory", async (t) => {
  if (process.platform === "win32") return;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "safeproof-storage-mode-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.chmod(directory, 0o750);
  await writeTextAtomic(path.join(directory, "proof.md"), "proof\n", { directoryMode: 0o755 });
  assert.equal((await fs.stat(directory)).mode & 0o777, 0o750);
});
