import { createHmac, createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.js";
import type { VerifyParams, VerifyResult } from "./types.js";

function base64url(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export async function verify(params: VerifyParams): Promise<VerifyResult> {
  const { envelope, secret, runtimeToolName, runtimeArguments, runtimeServerFingerprint, now: nowDate } = params;

  const resolveRef =
    params.resolveRef || (async () => new Uint8Array());
  const nonceCache = params.nonceCache || new Set<string>();

  const now = nowDate || new Date();

  // ── Rule 1: Signature verification ──
  const { signature, ...fields } = envelope;
  const payload = { ...fields, signature: "" };
  const canonical = canonicalize(payload);
  const expected = createHmac("sha256", secret).update(canonical).digest("hex");

  if (signature !== expected) {
    return { ok: false, reason: "signature_invalid" };
  }

  // ── Rule 2: Nonce replay check ──
  if (nonceCache.has(envelope.issuerAsserted.nonce)) {
    return { ok: false, reason: "nonce_replay" };
  }
  nonceCache.add(envelope.issuerAsserted.nonce);

  // ── Rule 3: TTL check ──
  const iat = new Date(envelope.issuerAsserted.iat).getTime();
  const ttl = envelope.issuerAsserted.expSeconds * 1000;
  const skewMs = 30_000;
  if (now.getTime() < iat - skewMs) {
    return { ok: false, reason: "expired" };
  }
  if (now.getTime() > iat + ttl + skewMs) {
    return { ok: false, reason: "expired" };
  }

  // ── Rule 4: Tool call match ──
  const entry = envelope.payloadDerived.toolCalls.find(
    (tc) => tc.serverFingerprint === runtimeServerFingerprint,
  );
  if (!entry) {
    return { ok: false, reason: "server_mismatch" };
  }
  if (entry.name !== runtimeToolName) {
    return { ok: false, reason: "tool_mismatch" };
  }

  // ── Rule 5: Argument commitment verification ──
  let projectionMatch: "identity" | "redacted" | null = null;

  if (entry.argsRef && entry.argsRef.uri) {
    const resolved = await resolveRef(entry.argsRef.uri);
    const digest = base64url(createHash("sha256").update(resolved).digest());
    if (digest !== entry.argsRef.digest) {
      return { ok: false, reason: "args_commitment_mismatch" };
    }
  }

  if (entry.argsProjection !== undefined) {
    const proj = JSON.parse(entry.argsProjection);
    const projCanon = canonicalize(proj);
    const runtimeCanon = canonicalize(runtimeArguments);
    projectionMatch = projCanon === runtimeCanon ? "identity" : "redacted";
  }

  if (!entry.argsRef && entry.argsProjection === undefined) {
    return { ok: false, reason: "args_commitment_mismatch" };
  }

  return { ok: true, reason: undefined, projectionMatch };
}
