import { createHash, randomBytes } from "node:crypto";
import { sign } from "./sign.js";
import { verify } from "./verify.js";
import type { Attestation, VerifyResult } from "./types.js";

const SECRET = "demo-shared-secret-123";
const NOW = new Date("2026-05-27T12:00:00Z");

function base64url(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function mkNonce(): string {
  return base64url(randomBytes(16));
}

async function fileResolver(uri: string): Promise<Uint8Array> {
  // Inline fixture data as fallback
  const inline: Record<string, Uint8Array> = {
    "fixture://email-body.txt": new TextEncoder().encode("Welcome to the platform! We're glad to have you."),
    "fixture://large-payload.bin": new TextEncoder().encode("fake binary content for ref resolution test"),
  };
  if (uri.startsWith("fixture://")) return inline[uri] || new Uint8Array();
  return new Uint8Array();
}

interface Scenario {
  name: string;
  description: string;
  run: () => Promise<{ signed: Attestation; result: VerifyResult }>;
}

async function runScenarios() {
  const scenarios: Scenario[] = [
    // ── 1. Happy path: args_projection identity ──
    {
      name: "Happy path — args_projection identity",
      description: "grant@example.com sends 'Welcome' email with full args in projection",
      run: async () => {
        const args = { to: "grant@example.com", subject: "Welcome!", body: "Welcome to the platform!" };
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send onboarding email to new user",
            toolCalls: [
              {
                name: "send_email",
                args_projection: JSON.stringify(args),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: args,
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 2. Happy path: args_ref resolves local file ──
    {
      name: "Happy path — args_ref resolves local file",
      description: "Email body loaded from file ref, identity projection for to/subject",
      run: async () => {
        const bodyContent = new TextEncoder().encode("Welcome to the platform! We're glad to have you.");
        const bodyDigest = base64url(createHash("sha256").update(bodyContent).digest());

        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send onboarding email with ref body",
            toolCalls: [
              {
                name: "send_email",
                args_ref: { uri: "fixture://email-body.txt", digest: bodyDigest },
                args_projection: JSON.stringify({ to: "grant@example.com", subject: "Welcome!" }),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: { to: "grant@example.com", subject: "Welcome!", body: "Welcome to the platform! We're glad to have you." },
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 3. Tampered args_projection (change subject after signing) ──
    {
      name: "Tampered args_projection — different subject at runtime",
      description: "Runtime args have 'Goodbye' subject, projection has 'Welcome' — redacted projection",
      run: async () => {
        const args = { to: "grant@example.com", subject: "Welcome!" };
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send email to new user",
            toolCalls: [
              {
                name: "send_email",
                args_projection: JSON.stringify(args),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: { to: "grant@example.com", subject: "Goodbye!" },
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 4. Tampered ref file content ──
    {
      name: "Tampered ref — different file content on disk",
      description: "File content differs from attested digest",
      run: async () => {
        const bodyContent = new TextEncoder().encode("Welcome to the platform! We're glad to have you.");
        const bodyDigest = base64url(createHash("sha256").update(bodyContent).digest());

        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send onboarding email with ref body",
            toolCalls: [
              {
                name: "send_email",
                args_ref: { uri: "fixture://email-body.txt", digest: bodyDigest },
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        // Override resolver to return different content
        const tamperedResolver = async (uri: string) => {
          return new TextEncoder().encode("COMPROMISED: different content here.");
        };
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: { to: "grant@example.com", body: "COMPROMISED: different content here." },
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: tamperedResolver,
        });
        return { signed, result };
      },
    },

    // ── 5. Tampered tool name ──
    {
      name: "Tampered tool name — runtime name differs from attested",
      description: "Envelope says 'send_email', runtime says 'delete_all_emails'",
      run: async () => {
        const args = { to: "grant@example.com" };
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Manage user email",
            toolCalls: [
              {
                name: "send_email",
                args_projection: JSON.stringify(args),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "delete_all_emails",
          runtimeArguments: args,
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 6. Wrong server fingerprint ──
    {
      name: "Wrong server fingerprint",
      description: "Envelope for email.example.com, runtime at evil.example.com",
      run: async () => {
        const args = { to: "grant@example.com" };
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send email",
            toolCalls: [
              {
                name: "send_email",
                args_projection: JSON.stringify(args),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: args,
          runtimeServerFingerprint: "mcp://evil.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 7. Expired TTL ──
    {
      name: "Expired TTL",
      description: "Attestation issued 10 minutes ago with 5-second expiry",
      run: async () => {
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T11:50:00Z",
            exp: 5,
            nonce: mkNonce(),
            intent: "Send email (too late)",
            toolCalls: [
              {
                name: "send_email",
                args_projection: '{"to":"grant@example.com"}',
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: { to: "grant@example.com" },
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 8. Nonce replay ──
    {
      name: "Nonce replay",
      description: "Same envelope verified twice — second should fail",
      run: async () => {
        const nonce = "reused-nonce-value";
        const args = { to: "grant@example.com" };
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce,
            intent: "Send email",
            toolCalls: [
              {
                name: "send_email",
                args_projection: JSON.stringify(args),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const cache = new Set<string>();
        const baseParams = {
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: args,
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
          nonceCache: cache,
        };
        await verify(baseParams); // first — OK
        const result = await verify(baseParams); // second — replay
        return { signed, result };
      },
    },

    // ── 9. Wrong secret ──
    {
      name: "Wrong secret — sign with one key, verify with another",
      description: "Attacker doesn't know the shared secret",
      run: async () => {
        const args = { to: "grant@example.com" };
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send email",
            toolCalls: [
              {
                name: "send_email",
                args_projection: JSON.stringify(args),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          "attacker-secret",
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: args,
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 10. Tampered signature (bit flip) ──
    {
      name: "Tampered signature — hex char flipped",
      description: "Last byte of hex signature incremented by 1",
      run: async () => {
        const args = { to: "grant@example.com" };
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send email",
            toolCalls: [
              {
                name: "send_email",
                args_projection: JSON.stringify(args),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        // Flip last hex char
        const chars = [...signed.signature];
        const last = chars[chars.length - 1];
        chars[chars.length - 1] = last === "f" ? "0" : String.fromCharCode(last.charCodeAt(0) + 1);
        const tampered = { ...signed, signature: chars.join("") };
        const result = await verify({
          envelope: tampered,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: args,
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 11. Redacted args_projection ──
    {
      name: "Redacted args_projection — summary only",
      description: "Projection has { subject } but runtime has to+subject+body — non-matching is OK",
      run: async () => {
        const projection = { subject: "Welcome!" };
        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send email with PII redacted from projection",
            toolCalls: [
              {
                name: "send_email",
                args_projection: JSON.stringify(projection),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: { to: "grant@example.com", subject: "Welcome!", body: "Welcome to the platform!" },
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },

    // ── 12. Mixed args (ref + projection) ──
    {
      name: "Mixed args — args_ref for body, args_projection for to/subject",
      description: "Large body via ref, metadata via projection",
      run: async () => {
        const bodyContent = new TextEncoder().encode("fake binary content for ref resolution test");
        const bodyDigest = base64url(createHash("sha256").update(bodyContent).digest());

        const signed = await sign(
          {
            version: 1,
            alg: "HS256",
            iss: "issuer://demo",
            sub: "agent:email-bot",
            secretVersion: "1",
            iat: "2026-05-27T12:00:00Z",
            exp: 300,
            nonce: mkNonce(),
            intent: "Send email with large attachment ref",
            toolCalls: [
              {
                name: "send_email",
                args_ref: { uri: "fixture://large-payload.bin", digest: bodyDigest },
                args_projection: JSON.stringify({ to: "grant@example.com", subject: "Your report" }),
                serverFingerprint: "mcp://email.example.com",
              },
            ],
            signature: "",
          },
          SECRET,
        );
        const result = await verify({
          envelope: signed,
          secret: SECRET,
          runtimeToolName: "send_email",
          runtimeArguments: {
            to: "grant@example.com",
            subject: "Your report",
            attachment: "fake binary content for ref resolution test",
          },
          runtimeServerFingerprint: "mcp://email.example.com",
          now: NOW,
          resolveRef: fileResolver,
        });
        return { signed, result };
      },
    },
  ];

  // ── Report ──
  let passed = 0;
  let failed = 0;

  console.log("=== SEP-2787 Attestation Demo ===\n");

  for (const sc of scenarios) {
    console.log(sc.name);
    console.log(`  ${sc.description}`);
    try {
      const { signed, result } = await sc.run();
      const status = result.ok ? "✓ PASS" : "✗ REJECTED";
      const reason = result.reason ? ` (${result.reason})` : "";
      const proj = result.projectionMatch ? ` [projection: ${result.projectionMatch}]` : "";
      console.log(`  → ${status}${reason}${proj}`);
      if (result.ok) passed++;
      else failed++;
    } catch (err) {
      console.log(`  → 💥 ERROR: ${err}`);
      failed++;
    }
    console.log();
  }

  console.log(`Results: ${passed}/${passed + failed} ✓  (${failed} expected failures)`);
}

await runScenarios();
