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
  if (nonceCache.has(envelope.nonce)) {
    return { ok: false, reason: "nonce_replay" };
  }
  nonceCache.add(envelope.nonce);

  // ── Rule 3: TTL check ──
  const iat = new Date(envelope.iat).getTime();
  const ttl = envelope.exp * 1000;
  const skewMs = 30_000;
  if (now.getTime() > iat + ttl + skewMs) {
    return { ok: false, reason: "expired" };
  }

  // ── Rule 4: Tool call match ──
  const entry = envelope.toolCalls.find(
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

  if (entry.args_ref && entry.args_ref.uri) {
    const resolved = await resolveRef(entry.args_ref.uri);
    const digest = base64url(createHash("sha256").update(resolved).digest());
    if (digest !== entry.args_ref.digest) {
      return { ok: false, reason: "args_commitment_mismatch" };
    }
  }

  if (entry.args_projection !== undefined) {
    const proj = JSON.parse(entry.args_projection);
    const projCanon = canonicalize(proj);
    const runtimeCanon = canonicalize(runtimeArguments);
    projectionMatch = projCanon === runtimeCanon ? "identity" : "redacted";
  }

  if (!entry.args_ref && entry.args_projection === undefined) {
    return { ok: false, reason: "args_commitment_mismatch" };
  }

  return { ok: true, reason: undefined, projectionMatch };
}
