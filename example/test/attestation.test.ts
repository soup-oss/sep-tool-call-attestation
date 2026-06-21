import { describe, it, expect, beforeAll } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { sign } from "../src/sign.js";
import { verify } from "../src/verify.js";
import { canonicalize } from "../src/canonicalize.js";
import type { Attestation, VerifyResult } from "../src/types.js";

const SECRET = "test-secret-abc123";
const NOW = new Date("2026-06-01T00:00:00Z");

function base64url(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fixtureRef(contents: string): { uri: string; digest: string } {
  const buf = new TextEncoder().encode(contents);
  const digest = base64url(createHash("sha256").update(buf).digest());
  return { uri: `fixture://inline/${base64url(randomBytes(8))}`, digest };
}

function mkNonce(): string {
  return base64url(randomBytes(16));
}

async function makeEnvelope(
  overrides: Partial<Attestation> = {},
): Promise<Attestation> {
  const body = "Hello!";
  const args = { to: "a@b.com", subject: "Hi", body };
  const base: Attestation = {
    issuerAsserted: {
      alg: "HS256",
      iss: "issuer://test",
      sub: "agent:test-bot",
      secretVersion: "1",
      iat: "2026-06-01T00:00:00Z",
      expSeconds: 300,
      nonce: mkNonce(),
    },
    plannerDeclared: {
      intent: "Test attestation",
    },
    payloadDerived: {
      toolCalls: [
        {
          name: "test_tool",
          argsProjection: JSON.stringify(args),
          serverFingerprint: "mcp://test.example.com",
        },
      ],
    },
    signature: "",
  };
  return sign({ ...base, ...overrides }, SECRET);
}

describe("SEP-2787 Attestation", () => {
  // ── Happy path ──
  describe("Happy path", () => {
    it("1. argsProjection identity passes", async () => {
      const args = { to: "a@b.com", subject: "Hi", body: "Hello!" };
      const env = await makeEnvelope();
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: args,
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(true);
      expect(result.projectionMatch).toBe("identity");
    });

    it("2. argsRef resolves and passes", async () => {
      const contents = "file content here";
      const ref = fixtureRef(contents);
      const args = { to: "a@b.com", subject: "Hi" };
      const env = await makeEnvelope({
        payloadDerived: {
          toolCalls: [
            {
              name: "test_tool",
              argsRef: ref,
              argsProjection: JSON.stringify(args),
              serverFingerprint: "mcp://test.example.com",
            },
          ],
        },
      });
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { ...args, body: contents },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
        resolveRef: async () => new TextEncoder().encode(contents),
      });
      expect(result.ok).toBe(true);
    });

    it("3. Redacted projection passes", async () => {
      const env = await makeEnvelope({
        payloadDerived: {
          toolCalls: [
            {
              name: "test_tool",
              argsProjection: JSON.stringify({ subject: "Hi" }),
              serverFingerprint: "mcp://test.example.com",
            },
          ],
        },
      });
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(true);
      expect(result.projectionMatch).toBe("redacted");
    });
  });

  // ── Tamper / forge detection ──
  describe("Tamper detection", () => {
    it("4. Tampered signature fails", async () => {
      const env = await makeEnvelope();
      const chars = [...env.signature];
      chars[0] = chars[0] === "a" ? "b" : "a";
      const tampered = { ...env, signature: chars.join("") };
      const result = await verify({
        envelope: tampered,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("signature_invalid");
    });

    it("5. Wrong secret fails", async () => {
      const env = await makeEnvelope();
      const result = await verify({
        envelope: env,
        secret: "wrong-secret",
        runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("signature_invalid");
    });

    it("6. Tampered tool name fails", async () => {
      const env = await makeEnvelope();
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "evil_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("tool_mismatch");
    });

    it("7. Wrong server fingerprint fails", async () => {
      const env = await makeEnvelope();
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://evil.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("server_mismatch");
    });

    it("8. Tampered argsRef content fails", async () => {
      const ref = fixtureRef("real content");
      const env = await makeEnvelope({
        payloadDerived: {
          toolCalls: [
            {
              name: "test_tool",
              argsRef: ref,
              serverFingerprint: "mcp://test.example.com",
            },
          ],
        },
      });
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { body: "tampered content" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
        resolveRef: async () => new TextEncoder().encode("tampered content"),
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("args_commitment_mismatch");
    });
  });

  // ── TTL and replay ──
  describe("TTL and replay", () => {
    it("9. Expired TTL fails", async () => {
      const env = await makeEnvelope({
        issuerAsserted: {
          alg: "HS256",
          iss: "issuer://test",
          sub: "agent:test-bot",
          secretVersion: "1",
          iat: "2026-06-01T00:00:00Z",
          expSeconds: 5,
          nonce: mkNonce(),
        },
      });
      const later = new Date("2026-06-01T00:10:00Z");
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: later,
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("expired");
    });

    it("10. Nonce replay fails on second use", async () => {
      const cache = new Set<string>();
      const env = await makeEnvelope();
      const params = {
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
        nonceCache: cache,
      };
      const first = await verify(params);
      expect(first.ok).toBe(true);
      const second = await verify(params);
      expect(second.ok).toBe(false);
      expect(second.reason).toBe("nonce_replay");
    });

    it("11. Different nonces both pass", async () => {
      const cache = new Set<string>();
      const base = {
        alg: "HS256" as const,
        iss: "issuer://test",
        sub: "agent:test-bot",
        secretVersion: "1",
        iat: "2026-06-01T00:00:00Z",
        expSeconds: 300,
      };
      const env1 = await makeEnvelope({ issuerAsserted: { ...base, nonce: mkNonce() } });
      const env2 = await makeEnvelope({ issuerAsserted: { ...base, nonce: mkNonce() } });
      const r1 = await verify({
        envelope: env1, secret: SECRET, runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com", now: NOW, nonceCache: cache,
      });
      const r2 = await verify({
        envelope: env2, secret: SECRET, runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com", now: NOW, nonceCache: cache,
      });
      expect(r1.ok).toBe(true);
      expect(r2.ok).toBe(true);
    });

    it("12. Clock skew within 30s is tolerated", async () => {
      const env = await makeEnvelope({
        issuerAsserted: {
          alg: "HS256",
          iss: "issuer://test",
          sub: "agent:test-bot",
          secretVersion: "1",
          iat: "2026-06-01T00:00:00Z",
          expSeconds: 300,
          nonce: mkNonce(),
        },
      });
      const skewed = new Date("2026-06-01T00:05:25Z");
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: skewed,
      });
      expect(result.ok).toBe(true);
    });

    it("13. Clock skew beyond 30s fails", async () => {
      const env = await makeEnvelope({
        issuerAsserted: {
          alg: "HS256",
          iss: "issuer://test",
          sub: "agent:test-bot",
          secretVersion: "1",
          iat: "2026-06-01T00:00:00Z",
          expSeconds: 300,
          nonce: mkNonce(),
        },
      });
      const skewed = new Date("2026-06-01T00:05:35Z");
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: { to: "a@b.com", subject: "Hi", body: "Hello!" },
        runtimeServerFingerprint: "mcp://test.example.com",
        now: skewed,
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("expired");
    });
  });

  // ── Canonicalization stability ──
  describe("Canonicalization", () => {
    it("14. Same object always produces same canonical form", () => {
      const obj = { z: 1, a: { b: 2, c: [3, 1, 2] }, n: null };
      const c1 = canonicalize(obj);
      const c2 = canonicalize(obj);
      expect(c1).toBe(c2);
    });

    it("15. Reordered keys produce same canonical form", () => {
      const a = { foo: 1, bar: 2 };
      const b = { bar: 2, foo: 1 };
      expect(canonicalize(a)).toBe(canonicalize(b));
    });
  });

  // ── Correlation fields ──
  describe("Correlation fields", () => {
    it("17. Correlation fields are covered by the signature", async () => {
      const args = { to: "a@b.com" };
      const env = await sign({
        issuerAsserted: {
          alg: "HS256",
          iss: "issuer://test",
          sub: "agent:test-bot",
          secretVersion: "1",
          iat: "2026-06-01T00:00:00Z",
          expSeconds: 300,
          nonce: mkNonce(),
        },
        plannerDeclared: {
          intent: "Test correlation",
          sessionId: "sess_abc",
          turnId: "turn_1",
          toolCallId: "tc_99",
          agentLineage: "parent:alice/child:bob",
        },
        payloadDerived: {
          toolCalls: [
            { name: "test_tool", argsProjection: JSON.stringify(args), serverFingerprint: "mcp://test.example.com" },
          ],
        },
        signature: "",
      }, SECRET);

      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: args,
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(true);
    });

    it("18. Tampering with correlation field after signing fails", async () => {
      const args = { to: "a@b.com" };
      const env = await sign({
        issuerAsserted: {
          alg: "HS256",
          iss: "issuer://test",
          sub: "agent:test-bot",
          secretVersion: "1",
          iat: "2026-06-01T00:00:00Z",
          expSeconds: 300,
          nonce: mkNonce(),
        },
        plannerDeclared: {
          intent: "Test correlation",
          sessionId: "sess_abc",
        },
        payloadDerived: {
          toolCalls: [
            { name: "test_tool", argsProjection: JSON.stringify(args), serverFingerprint: "mcp://test.example.com" },
          ],
        },
        signature: "",
      }, SECRET);

      const tampered = {
        ...env,
        plannerDeclared: { ...env.plannerDeclared, sessionId: "sess_tampered" },
      };
      const result = await verify({
        envelope: tampered,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: args,
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("signature_invalid");
    });

    it("19. Correlation fields are optional — absent still passes", async () => {
      const args = { to: "a@b.com" };
      const env = await makeEnvelope({
        payloadDerived: {
          toolCalls: [
            { name: "test_tool", argsProjection: JSON.stringify(args), serverFingerprint: "mcp://test.example.com" },
          ],
        },
      });
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: args,
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(true);
    });
  });

  // ── Missing args commitment ──
  describe("Missing args commitment", () => {
    it("16. No argsRef or argsProjection fails", async () => {
      const env = await makeEnvelope({
        payloadDerived: {
          toolCalls: [
            {
              name: "test_tool",
              serverFingerprint: "mcp://test.example.com",
            },
          ],
        },
      });
      const result = await verify({
        envelope: env,
        secret: SECRET,
        runtimeToolName: "test_tool",
        runtimeArguments: {},
        runtimeServerFingerprint: "mcp://test.example.com",
        now: NOW,
      });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe("args_commitment_mismatch");
    });
  });
});
