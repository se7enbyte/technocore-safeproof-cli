"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

async function ensureDirectory(directory, mode = 0o700) {
  const created = await fs.mkdir(directory, { recursive: true, mode });
  if (created === undefined) return false;
  try {
    await fs.chmod(directory, mode);
  } catch (error) {
    if (process.platform !== "win32") throw error;
  }
  return true;
}

async function writeJsonAtomic(filePath, value, options = {}) {
  const directory = path.dirname(filePath);
  const mode = options.mode ?? 0o600;
  await ensureDirectory(directory, options.directoryMode ?? 0o700);
  const temporaryPath = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`,
  );
  const body = `${JSON.stringify(value, null, 2)}\n`;
  try {
    await fs.writeFile(temporaryPath, body, { encoding: "utf8", mode, flag: "wx" });
    await fs.rename(temporaryPath, filePath);
    try {
      await fs.chmod(filePath, mode);
    } catch (error) {
      if (process.platform !== "win32") throw error;
    }
  } catch (error) {
    await fs.unlink(temporaryPath).catch(() => {});
    throw error;
  }
}

async function readJson(filePath) {
  const body = await fs.readFile(filePath, "utf8");
  try {
    return JSON.parse(body);
  } catch (error) {
    throw new Error(`Invalid JSON in ${path.basename(filePath)}: ${error.message}`);
  }
}

async function writeTextAtomic(filePath, value, options = {}) {
  const directory = path.dirname(filePath);
  const mode = options.mode ?? 0o644;
  await ensureDirectory(directory, options.directoryMode ?? 0o755);
  const temporaryPath = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.tmp`,
  );
  try {
    await fs.writeFile(temporaryPath, String(value), { encoding: "utf8", mode, flag: "wx" });
    await fs.rename(temporaryPath, filePath);
  } catch (error) {
    await fs.unlink(temporaryPath).catch(() => {});
    throw error;
  }
}

module.exports = {
  ensureDirectory,
  readJson,
  writeJsonAtomic,
  writeTextAtomic,
};
