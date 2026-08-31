"use strict";

const DEFAULT_BASE_URL = "https://technocore.chat";

class TechnocoreError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "TechnocoreError";
    this.status = options.status || 0;
    this.body = options.body || "";
    this.retryAfter = options.retryAfter || "";
    this.outcome = options.outcome || "failed";
    this.cause = options.cause;
  }
}

function normalizeOrigin(value = DEFAULT_BASE_URL) {
  const url = new URL(String(value).trim());
  const isLocal = ["127.0.0.1", "localhost", "::1"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal)) {
    throw new Error("Technocore origin must use HTTPS (HTTP is allowed only for localhost tests).");
  }
  if (url.username || url.password || (url.pathname && url.pathname !== "/") || url.search || url.hash) {
    throw new Error("Technocore origin must not include credentials, a path, query, or fragment.");
  }
  return url.origin;
}

function encodeSegment(value) {
  return encodeURIComponent(String(value));
}

function queryString(params = {}) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") query.set(key, String(value));
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

class TechnocoreClient {
  constructor(options = {}) {
    this.baseUrl = normalizeOrigin(options.baseUrl || DEFAULT_BASE_URL);
    this.fetch = options.fetch || globalThis.fetch;
    this.timeoutMs = options.timeoutMs || 15000;
    this.readAttempts = options.readAttempts ?? 3;
    this.sleep = options.sleep || ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    if (typeof this.fetch !== "function") throw new Error("A fetch implementation is required.");
    if (!Number.isInteger(this.readAttempts) || this.readAttempts < 1 || this.readAttempts > 3) {
      throw new Error("Read attempts must be an integer from 1 to 3.");
    }
  }

  async request(path, options = {}) {
    const attempts = options.isWrite === true ? 1 : this.readAttempts;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        return await this.requestOnce(path, options);
      } catch (error) {
        const retryableRead = error instanceof TechnocoreError
          && options.isWrite !== true
          && (error.status === 0 || error.status >= 500);
        if (!retryableRead || attempt === attempts) throw error;
        await this.sleep(attempt === 1 ? 1000 : 3000);
      }
    }
    throw new Error("Unreachable request retry state.");
  }

  async requestOnce(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || this.timeoutMs);
    const isWrite = options.isWrite === true;
    let response;
    let body;
    try {
      response = await this.fetch(`${this.baseUrl}${path}`, {
        method: options.method || "GET",
        headers: options.headers,
        body: options.body,
        redirect: "error",
        signal: controller.signal,
      });
      body = await response.text();
    } catch (error) {
      const timedOut = error && error.name === "AbortError";
      throw new TechnocoreError(
        timedOut ? "Technocore request timed out." : "Technocore request ended before a complete response was received.",
        {
          cause: error,
          status: response && Number.isInteger(response.status) ? response.status : 0,
          outcome: isWrite ? "unknown" : "failed",
        },
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new TechnocoreError(`Technocore returned HTTP ${response.status}.`, {
        status: response.status,
        body,
        retryAfter: response.headers.get("retry-after") || "",
        outcome: isWrite && response.status >= 500 ? "unknown" : "failed",
      });
    }
    return {
      status: response.status,
      body,
      contentType: response.headers.get("content-type") || "",
    };
  }

  async health() {
    return this.request("/healthz", { timeoutMs: Math.min(this.timeoutMs, 5000) });
  }

  async readNote(ns, key) {
    return this.request(`/kv/${encodeSegment(ns)}/${encodeSegment(key)}`);
  }

  async writeNote(ns, key, value, condition = { ifAbsent: true }) {
    const payload = { value };
    if (condition.ifAbsent === true) payload.if_absent = true;
    if (condition.expected !== undefined) payload.if = condition.expected;
    return this.request(`/kv/${encodeSegment(ns)}/${encodeSegment(key)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      isWrite: true,
    });
  }

  async readRoom(room, options = {}) {
    const result = await this.request(
      `/r/${encodeSegment(room)}${queryString({
        format: "json",
        since: options.since,
        limit: options.limit || 200,
        n: options.cacheBust || Date.now(),
      })}`,
    );
    try {
      return { ...result, json: JSON.parse(result.body) };
    } catch (error) {
      throw new TechnocoreError("Technocore room response was not valid JSON.", {
        status: result.status,
        body: result.body,
        cause: error,
      });
    }
  }

  async writeSignedRoom(room, signedMessage) {
    return this.request(`/r/${encodeSegment(room)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        did: signedMessage.did,
        sig: signedMessage.sig,
        nonce: String(signedMessage.nonce),
        text: signedMessage.text,
      }),
      isWrite: true,
    });
  }
}

module.exports = {
  DEFAULT_BASE_URL,
  TechnocoreClient,
  TechnocoreError,
  normalizeOrigin,
};
