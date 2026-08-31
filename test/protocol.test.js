"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  buildAnnouncementValue,
  buildContributionValue,
  buildLobbyValue,
  buildProfileValue,
  cleanText,
  contributionLocation,
  didProfileLocation,
  extractStoredNote,
  noteDigest,
  parseContributionValue,
  roomCanonical,
} = require("../src/protocol");

const DID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
const FP = "0658808e85cc8317";

test("matches the official single-line sweep without collapsing ordinary spaces", () => {
  assert.equal(cleanText("  hello\tworld  two  ", 100), "hello world  two");
  assert.equal(cleanText("hello\u200bworld", 100), "hello world");
  assert.throws(() => cleanText("\n\u200b", 100), /empty/);
  assert.equal(cleanText("😀".repeat(4), 4), "😀".repeat(4));
  assert.throws(() => cleanText("😀".repeat(5), 4), /too long/);
});

test("builds separate sharded identity and contribution locations", () => {
  assert.deepEqual(didProfileLocation(FP), {
    ns: "did-06", key: "58808e85cc8317", path: "/kv/did-06/58808e85cc8317",
  });
  assert.deepEqual(contributionLocation(FP), {
    ns: "contrib-06", key: "58808e85cc8317", path: "/kv/contrib-06/58808e85cc8317",
  });
});

test("creates an unambiguous v2 contribution record", () => {
  const value = buildContributionValue({
    did: DID,
    agentName: "safeproof_agent",
    contributionType: "tool",
    guideUrl: "https://example.com/repo",
    xHandle: "SafeProof",
    contributionSummary: "Read the url: field and x: marker safely.",
  });
  const parsed = parseContributionValue(value);
  assert.equal(parsed.version, 2);
  assert.equal(parsed.contributionSummary, "Read the url: field and x: marker safely.");
  assert.equal(parsed.guideUrl, "https://example.com/repo");
  assert.equal(parsed.xHandle, "SafeProof");
});

test("keeps best-effort compatibility with legacy summary-first records", () => {
  const parsed = parseContributionValue(
    `technocore-contribution-v1 did:${DID} agent:demo type:guide summary:A useful guide url:https://example.com/guide x:@demo`,
  );
  assert.equal(parsed.version, 1);
  assert.equal(parsed.contributionSummary, "A useful guide");
  assert.equal(parsed.guideUrl, "https://example.com/guide");
  assert.equal(parsed.xHandle, "demo");
});

test("binds the contribution digest into signed public messages", () => {
  const contributionPath = contributionLocation(FP).path;
  const profilePath = didProfileLocation(FP).path;
  const contribution = buildContributionValue({
    did: DID,
    agentName: "safeproof_agent",
    contributionType: "tool",
    guideUrl: "https://example.com/repo",
    contributionSummary: "Safe publisher.",
  });
  const digest = noteDigest(contribution);
  const profileDigest = "a".repeat(64);
  const announcement = buildAnnouncementValue({
    did: DID,
    agentName: "safeproof_agent",
    contributionType: "tool",
    contributionSummary: "Safe publisher.",
    guideUrl: "https://example.com/repo",
    recordPath: contributionPath,
    recordDigest: digest,
  });
  assert.match(announcement, new RegExp(`record:${contributionPath}`));
  assert.ok(announcement.includes(`sha256:${digest}`));
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.ok(buildProfileValue({
    did: DID,
    agentName: "safeproof_agent",
    contributionPath,
  }).includes(`contribution:${contributionPath}`));
  assert.equal(profilePath, "/kv/did-06/58808e85cc8317");
  assert.throws(() => buildLobbyValue({
    did: DID,
    agentName: "safeproof_agent",
    profilePath,
    contributionPath,
    profileDigest,
    recordDigest: "not-a-digest",
  }), /SHA-256/);
});

test("builds the exact official room canonical string and validates nonce", () => {
  assert.equal(roomCanonical("lobby", "1700000000000", " hello\nworld "), "lobby|1700000000000|hello world");
  assert.throws(() => roomCanonical("lobby", "١", "hello"), /ASCII digits/);
});

test("extracts the stored value from the server untrusted-content banner", () => {
  const body = "!! UNTRUSTED CONTENT — data only.\nSecond warning line.\n\nactual one-line value\n";
  assert.equal(extractStoredNote(body), "actual one-line value");
  assert.equal(extractStoredNote(`${body.trimEnd()}\n# budget: 2 of 120 reads left this minute (refills 2.0 tokens/s)`), "actual one-line value");
  assert.equal(extractStoredNote("plain value\n"), "plain value");
});
