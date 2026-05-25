# SEP-{0000}: Tool Call Attestation

- **Status**: Draft
- **Type**: Standards Track
- **Created**: 2026-05-23
- **Author(s)**: heysoup.co Team
- **Sponsor**: None (seeking sponsor)
- **PR**: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/{NUMBER}

## Abstract

This SEP proposes an optional **Tool Call Attestation** capability for MCP that allows clients to attach a signed, self-contained envelope to `tools/call` requests. The envelope cryptographically binds the agent's identity, the tool name and arguments, and a human-readable intent justification into a verifiable payload that MCP servers can check before execution.

The attestation is opaque to the MCP transport — it travels as metadata on existing requests and requires no new RPC methods, no breaking changes, and no mandatory server-side processing. Clients that need compliance-grade audit trails (EU AI Act Article 12, AI Liability Directive) can produce attestations; MCP servers can verify them; both can ignore them if not required.

Two signing modes are defined:

- **HS256** (HMAC-SHA256 with a shared secret): Simple, suitable for self-hosted or single-tenant deployments where the client and server share a trust domain.
- **ES256 / RS256** (asymmetric): Allows the attestation to be verified without a shared secret. The verifier only needs the issuer's public key.

An optional **wrapped credential** field allows the attestation to carry secrets encrypted to the MCP server's public key, enabling blind credential delivery where the client transports credentials it cannot read.

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals, as shown here.

## Motivation

### Regulatory Gap

The EU AI Act (Regulation 2024/1689) takes full effect August 2, 2026. Article 12 requires high-risk AI systems to automatically record every event with sufficient detail to reconstruct the system's operation. Article 26(6) mandates minimum 6-month log retention. The AI Liability Directive creates a rebuttable presumption of causality if the operator cannot produce an adequate audit trail.

MCP today provides transport (STDIO, HTTP/SSE) and an Authorization framework, but **no mechanism to bind a tool call to an agent's identity, documented intent, or expected state mutation**. Every MCP tool call executes without cryptographic attestation. There is no standard way for an MCP server to verify that a tool call was authorized by a known identity with a recorded business justification.

Without this capability, MCP deployments in regulated environments face fragmentation — each implementation ships a proprietary attestation header, undermining interoperability across the ecosystem.

### Existing Practice

Several MCP implementations already carry agent identity or session tokens in `_meta`. However, none standardize:

- The schema of the signed attestation payload.
- The verification rules (nonce replay protection, TTL enforcement, key selection).
- The transport encoding for attestations across HTTP and JSON-RPC.
- The optional credential wrapping mechanism.

This SEP fills that gap by defining a minimal, composable attestation envelope that can be adopted incrementally.

## Specification

### Capability Negotiation

MCP servers that support attestation advertise it in their `serverCapabilities` during initialization:

```typescript
interface ServerCapabilities {
  // ... existing fields
  tools?: {
    // ... existing fields
    attestation?: {
      /** Supported signing algorithms */
      algorithms: Array<"HS256" | "ES256" | "RS256">;
      /** Server requires attestation on all tool calls */
      required?: boolean;
      /** Server supports wrapped credentials */
      credentialDelivery?: boolean;
      /** Server can find its entry in a multi-server array */
      multiServer?: boolean;
    };
  };
}
```

Clients that wish to use attestation include a matching capability in `clientCapabilities`:

```typescript
interface ClientCapabilities {
  // ... existing fields
  tools?: {
    // ... existing fields
    attestation?: {
      algorithms: Array<"HS256" | "ES256" | "RS256">;
      credentialDelivery?: boolean;
    };
  };
}
```

If a server advertises `required: true`, clients MUST include a valid attestation on every `tools/call` request or the server MUST reject the call with an error.

### Attestation Envelope

The attestation is a signed JSON object sent as part of the `tools/call` request metadata. It is self-contained: the verifier does not need a connection to the issuer.

```typescript
/** @meta/_meta/attestation — sent alongside tools/call */
interface Attestation {
  /** Protocol version. MUST be 1. */
  version: 1;

  /** Signing algorithm used for `signature`.
   *  "HS256": HMAC-SHA256 (shared secret).
   *  "ES256": ECDSA P-256 SHA-256.
   *  "RS256": RSASSA-PKCS1-v1_5 SHA-256.
   */
  alg: "HS256" | "ES256" | "RS256";

  /** Issuer identifier. Opaque string meaningful to the verifier.
   *  Example: "issuer://a1b2c3d4-e5f6-7890-abcd-ef1234567890"
   */
  iss: string;

  /** Subject identifier. The agent or entity making the call.
   *  Example: "agent:deploy-bot"
   */
  sub: string;

  /** Human-readable justification for the tool call(s).
   *  MUST be non-empty when present.
   */
  intent: string;

  /** One or more tool calls signed by this attestation.
   *  Each MCP server verifies only the entry where
   *  serverFingerprint matches its own identity.
   *  If credentialDelivery is used, individual entries
   *  can reference a key in wrappedCredentials.
   */
  toolCalls: Array<{
    name: string;
    /** Tool arguments serialized as canonical JSON string.
     *
     *  If the string starts with `"resource: https://..."` (or any
     *  other protocol), the arguments are stored at that URL and
     *  MUST NOT be attested inline. Instead, the issuer fetches
     *  the content from the URL, computes SHA-256, and attests
     *  the resolved form `{ "resource": "<url>", "digest": "sha256:<hex>" }`.
     *  This keeps the attestation size independent of argument payload.
     *
     *  If the string does NOT start with `"resource: "`, the value
     *  is attested inline as-is. The verifier parses and re-serializes
     *  canonical JSON for signature verification, then passes the
     *  parsed object to the tool handler.
     */
    args: string;
    serverFingerprint: string;
    /** Optional. Key into wrappedCredentials dict.
     *  If omitted and wrappedCredentials has exactly one entry,
     *  that entry is used. If omitted and wrappedCredentials has
     *  zero or multiple entries, the server MUST reject.
     */
    credentialRef?: string;
  }>;

  /** Version of the signing key. Enables key rotation without
   *  invalidating in-flight attestations. Verifiers MUST use
   *  this value to select the correct key for verification.
   */
  secretVersion: string;

  /** ISO 8601 UTC timestamp of when the attestation was issued. */
  iat: string;

  /** Seconds from iat until this attestation expires.
   *  Verifiers MUST reject expired attestations.
   *  RECOMMENDED maximum: 300 (5 minutes).
   */
  exp: number;

  /** Cryptographic nonce unique to this attestation.
   *  Verifiers MUST reject previously seen nonces within
   *  the TTL window. RECOMMENDED: 16+ bytes base64url-encoded.
   */
  nonce: string;

  /** HMAC or public-key signature computed over the canonical
   *  JSON representation (sorted keys, no whitespace) of all
   *  above fields EXCEPT this one.
   *  Encoding depends on the signing algorithm:
   *  - HS256: hex-encoded HMAC-SHA256 output (64 hex chars).
   *  - ES256: hex-encoded raw r||s concatenation (128 hex chars).
   *    Implementations MUST NOT use DER encoding.
   *  - RS256: hex-encoded RSASSA-PKCS1-v1_5 output.
   */
  signature: string;

  /** Optional. Dictionary of wrapped credentials, each encrypted
   *  to a specific MCP server's public key. Keys are opaque
   *  refs referenced by toolCalls[].credentialRef.
   *  The client carries but cannot decrypt any of these values.
   *  Encoded as base64url strings.
   *
   *  Reserved key "_ack": opaque proof token encrypted to the
   *  issuer's key, not the MCP server's. The MCP server MUST
   *  NOT attempt to decrypt it. Instead, the server signs the
   *  value as-is with its registered key and POSTs it back to
   *  the issuer's ack endpoint at `{iss}/_ack`. Only the issuer
   *  can decode the _ack and verify the server's signature.
   *  See "Acknowledgement Protocol" for details.
   */
  wrappedCredentials?: Record<string, string>;
}
```

### Canonical JSON for Signing

The signature is computed over a deterministic JSON representation:

1. Start with all fields of the `Attestation` object EXCEPT `signature`.
2. **Resource dereference**: For each entry in `toolCalls`, if `args` is a string that starts with `"resource: "`, the issuer MUST fetch the content at that URL, compute `sha256(content)`, and replace `args` with the canonical JSON string of `{ "resource": "<url>", "digest": "sha256:<hex>" }`. This is done BEFORE serialization — the signature covers the resolved form, not the resource reference.
3. Serialize using **sorted keys** (lexicographic order at every nesting level), **no whitespace**, **no trailing newline**.
4. The resulting UTF-8 byte string is the signing payload.

```python
# Example: Python-style canonicalization
payload = canonical_json({k: v for k, v in attestation.items() if k != "signature"})
signature = hex(hmac_sha256(secret, payload))  # for HS256
```

### Transport Encoding

#### HTTP Transport

For HTTP transports, the attestation is carried in a request header:

```
X-MCP-Attestation: <base64url(canonicalJSON(attestation))>
```

The server decodes the header, verifies the signature, checks the nonce and TTL, then processes the tool call.

#### JSON-RPC Transport

For JSON-RPC (STDIO, SSE), the attestation is carried in the `_meta` field of the `tools/call` request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "delete_file",
    "arguments": { "path": "/archive/2024-Q3.md" },
    "_meta": {
      "attestation": { /* Attestation object */ }
    }
  }
}
```

### Verification Rules

MCP servers that advertise `tools.attestation` MUST implement the following verification:

1. **Signature verification**: Decode the canonical JSON, verify the signature using the key identified by `alg` and `secretVersion`. For HS256, the shared secret must be pre-configured or derived. For ES256/RS256, the issuer's public key must be retrievable (e.g., from a key server, pre-shared, or published at a well-known URL matching `iss`).

2. **Nonce replay check**: Reject attestations whose `nonce` has been seen within `iat + exp`. RECOMMENDED: an in-memory bloom filter with background GC, or a bounded cache with the TTL window as the eviction horizon.

3. **TTL check**: Reject if `iat + exp < now()`. Allow up to 30 seconds of clock skew between issuer and verifier. Beyond that, the attestation MUST be rejected.

4. **Resource verification (if applicable)**: For the matched `toolCalls` entry, if `args` is a JSON object containing `resource` and `digest` keys, the server MUST fetch the content at `args.resource`, compute `sha256(content)`, and compare against `args.digest`. If the digests do not match, the server MUST reject with `resource_digest_mismatch`. If the resource is unreachable, the server MAY reject or proceed at its discretion (network conditions vary).

5. **Tool call match**: Find the entry in `toolCalls` where `serverFingerprint` matches the receiving server's identity. If no such entry exists, reject with `server_mismatch`. Then verify that the entry's `name` matches the `name` parameter of the `tools/call` request. If not, reject with `tool_mismatch`. This prevents cross-server replay and tool-substitution in a single step.

Servers that do not advertise `multiServer: true` MAY reject attestations where `toolCalls.length > 1`.

If any check fails, the server MUST return a tool result with `isError: true` and a structured error payload in the content:

```typescript
{
  result: {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify({
          attestation_error: true,
          reason: "signature_invalid" | "nonce_replay" | "expired" |
                  "tool_mismatch" | "server_mismatch" | "key_unavailable" |
                  "resource_digest_mismatch" | "credential_not_found" |
                  "credential_ambiguous" | "credential_decryption_failed" |
                  "attestation_required"
        })
      }
    ]
  }
}
```

Attestation failures are tool execution errors (the tool was not executed due to a failed security check), not protocol errors. They MUST be communicated as tool results, not JSON-RPC errors. This preserves the distinction MCP makes between protocol-level issues (malformed request, unknown method) and execution-level issues (policy rejection, security check failure).

### Credential Delivery (Optional)

If `credentialDelivery: true` is negotiated, the attestation MAY include a `wrappedCredentials` dictionary. Each value is a credential (API key, connection string, JWT, etc.) encrypted to the target MCP server's public key. The keys are opaque refs referenced by individual entries in `toolCalls[].credentialRef`.

Encryption mechanism:

- **For RSA keys**: RSA-OAEP with SHA-256.
- **For EC keys**: ECIES with AES-256-GCM content encryption.

Resolution rules:

- If `toolCalls[i].credentialRef` is set → the server looks up `wrappedCredentials[credentialRef]`. If the key does not exist, the server MUST reject with `credential_not_found`.
- If `credentialRef` is omitted and `wrappedCredentials` has exactly one entry → the server uses that single entry.
- If `credentialRef` is omitted and `wrappedCredentials` has zero entries → the call carries no credential (tool may not require one).
- If `credentialRef` is omitted and `wrappedCredentials` has multiple entries → the server MUST reject with `credential_ambiguous`.

On the MCP server:

1. Resolves the credential via the rules above.
2. Decrypts the resolved entry to obtain the plaintext.
3. Uses the credential for the tool call's authentication/authorization.
4. SHOULD zeroize the credential in memory after the tool call completes.

The client never has access to the plaintext credential.

### Error Reasons

Attestation failures are communicated as tool results with `isError: true`. The structured error payload in the content text uses the following `reason` values:

| Reason | Description |
|--------|-------------|
| `signature_invalid` | Signature does not match the canonical payload |
| `nonce_replay` | Nonce has been seen within the TTL window |
| `expired` | `iat + exp` has passed |
| `tool_mismatch` | Tool name does not match the `tools/call` request |
| `server_mismatch` | No `toolCalls` entry matches the receiving server's fingerprint |
| `key_unavailable` | Key identified by `alg` and `secretVersion` is not available |
| `resource_digest_mismatch` | Content fetched at `args.resource` does not match the attested digest |
| `credential_not_found` | The credential referenced by `credentialRef` does not exist in `wrappedCredentials` |
| `credential_ambiguous` | `credentialRef` omitted but `wrappedCredentials` has multiple entries |
| `credential_decryption_failed` | The wrapped credential could not be decrypted |
| `attestation_required` | Server requires attestation but none was provided |

## Rationale

### Why Optional Capability

Making attestation optional rather than mandatory ensures backward compatibility. Existing MCP clients and servers continue to work unchanged. New deployments can opt-in gradually. This follows the same pattern as MCP's existing Authorization framework — defined in the spec but negotiated at initialization.

### Why Two Signing Modes

**HS256** (symmetric HMAC) is the simplest deployment: the client and server share a secret. It is appropriate for self-hosted OSS deployments where both sides are in the same trust domain. No public key infrastructure is needed.

**ES256/RS256** (asymmetric) supports deployments where the client and server are in different trust domains. The verifier only needs the issuer's public key, which can be published, pre-shared as a fingerprint, or retrieved from a registry. This is the mode required for multi-tenant or enterprise scenarios where the issuer is a separate service (notary, compliance gateway, credential authority).

### Why Nonce + TTL Instead of Prevents-Replay

A nonce cache bounded by the attestation TTL is simpler and more robust than relying on monotonically increasing counters across potentially unreliable clients. The TTL prevents unbounded nonce storage. Thirty-second clock skew tolerance covers typical NTP drift margins.

### Why toolCalls Array

Using an array instead of a single `toolName`/`toolArgs`/`serverFingerprint` trio handles two use cases without protocol bloat. First, the common case is a single call — `toolCalls` has one entry, the server verifies against it, done. Second, multi-step workflows where an agent orchestrates across several MCP servers get a single attestation for the entire plan. Each server finds its own entry via `serverFingerprint`, and the shared nonce prevents partial replay. The signature covers the whole array — no entry can be inserted or removed after issuance.

### Why Resource References for Args

Large tool call arguments (e.g., file contents, image data, verbose configuration) would inflate the attestation envelope if included inline. By allowing `args` to reference an external URL that the issuer dereferences and hashes, the attestation remains small and constant-size regardless of payload. The issuer acts as a notary that verifies content at signing time — the attestation proves "the content at this URL had this digest when the attestation was issued," not just "the agent claimed it had this digest." This keeps the verification path trustless: the verifier fetches the URL independently and confirms the digest matches the attested value.

### Relationship to Authorization

Attestation is orthogonal to MCP's existing Authorization framework. Authorization proves *who* is allowed to call a tool. Attestation proves *why* they are calling it and *that* they called it. A deployment may use both: OAuth for transport-level auth and attestation for intent-bound audit.

## Backward Compatibility

**Fully backward compatible.** The attestation capability is negotiated at initialization. Servers that do not advertise `tools.attestation` never receive attestation metadata. Clients that do not support it never send it. Existing MCP implementations are completely unaffected.

Attestation errors are returned as tool execution errors (`isError: true`), not JSON-RPC protocol errors. This is consistent with how MCP handles other security-related tool execution failures and introduces no new JSON-RPC error codes.

## Security Implications

### Attestation Replay

The nonce + TTL mechanism prevents replay within the validity window. However, if the verifier's nonce cache is lost (e.g., process restart), previously valid attestations could be replayed until their TTL expires. Servers SHOULD persist nonce state for the maximum expected TTL if crash recovery is a concern.

### Key Compromise

If the issuer's signing key (HS256 shared secret or ES256/RS256 private key) is compromised, an attacker can forge attestations. Recovery requires key rotation — the `secretVersion` field allows verifiers to distinguish attestations signed with the old key from those signed with the new key during the rotation window.

### Clock Skew Attacks

Verifiers allow up to 30 seconds of clock skew. An attacker who can skew the verifier's clock can extend the replay window. Servers SHOULD monitor clock drift and reject attestations if system time diverges from NTP by more than 30 seconds.

### Side-Channel in Credential Wrapping

The wrapped credential is encrypted to the MCP server's public key. It is opaque to the client. However, during decryption on the MCP server, the credential exists in plaintext in the server's memory. MCP servers handling sensitive credentials SHOULD operate in isolated environments (sandboxed containers, confidential computing) to minimize exposure.

### Privacy Considerations

The `intent` field is human-readable and signed. It is visible to both the client and the MCP server in plaintext. Deployments handling sensitive intent descriptions SHOULD consider whether additional encryption of the intent field is required — this is out of scope for the current SEP but could be addressed in a future extension.

The `serverFingerprint` field identifies which MCP server was the target of a tool call. In multi-tenant or cross-org deployments, the set of servers an agent calls may reveal deployment topology, vendor relationships, or internal tooling choices. Deployments SHOULD evaluate whether the fingerprint alone constitutes sensitive metadata in their regulatory context.

The `iss` field identifies the attestation issuer. In deployments where the issuer is a dedicated notary or compliance service, the issuer's identity is public by design — the attestation is meant to be verifiable by third parties. However, the issuer's request volume (inferred from attestation issuance rate) may leak operational metadata. Issuers concerned about traffic analysis MAY consider deploying behind a privacy-preserving relay.

### Acknowledgement Protocol

The `_ack` reserved key (see wrappedCredentials definition) serves dual purposes as both a lightweight DDoS mitigation and an execution confirmation signal:

1. **Source authentication (DDoS mitigation)**: The `_ack` is signed with the MCP server's private key (the same key used for `wrappedCredentials` decryption, or a dedicated signing key). The client never has access to this key. By requiring the server to POST a signed opaque blob to `{iss}/_ack`, the issuer gains cryptographic proof that the identified MCP server — and only that server — received and acknowledged the attestation. An attacker who floods the issuer with attestation requests cannot complete the handshake without the server's key, so the `_ack` acts as a liveness check bound to a specific trusted identity.

2. **Execution confirmation**: The `_ack` payload is encrypted to the issuer and opaque to the MCP server. It embeds the tool call result (or a digest thereof) so the issuer can later verify that the attested tool call actually ran and produced the expected outcome, closing the loop between intent and result.

Limitations: The `_ack` provides source authentication but not execution truthfulness — a compromised server can sign a lie about what it executed. The issuer knows *who* acknowledged but cannot cryptographically prove *what actually ran*. Full acknowledgement semantics (retry, timeout, error codes, non-repudiation) are deferred to a follow-up SEP.

## Reference Implementation

A reference implementation will be provided as part of soup-oss, an MIT-licensed project. The implementation will include:

- Payload construction and canonicalization
- HS256 signing and verification
- Nonce generation and TTL enforcement
- Server fingerprint matching
- An MCP server adapter that verifies attestations before forwarding to tool handlers

## IANA Considerations

This SEP defines the following provisional values for MCP registries:

### Capability Name

- **Capability**: `tools.attestation`
- **Type**: Server capability (advertised in `serverCapabilities.tools.attestation`)
- **Status**: Provisional

### Signing Algorithm Identifiers

The following algorithm identifiers are defined for use in the `alg` field of the `Attestation` envelope:

| Identifier | Algorithm | Reference |
|------------|-----------|-----------|
| `HS256` | HMAC-SHA256 | RFC 7518 §3.2 |
| `ES256` | ECDSA using P-256 and SHA-256 | RFC 7518 §3.4 |
| `RS256` | RSASSA-PKCS1-v1_5 using SHA-256 | RFC 7518 §3.1 |

These identifiers are drawn from the JSON Web Signature (JWS) registry [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518). No new algorithm registrations are required.

### Error Reason Identifiers

Attestation verification failures use structured error payloads in tool results (see Verification Rules). The following `reason` strings are defined:

| Reason | Description |
|--------|-------------|
| `signature_invalid` | Signature does not match the canonical payload |
| `nonce_replay` | Nonce has been seen within the TTL window |
| `expired` | `iat + exp` has passed |
| `tool_mismatch` | Tool name does not match the `tools/call` request |
| `server_mismatch` | No `toolCalls` entry matches the receiving server's fingerprint |
| `key_unavailable` | Key identified by `alg` and `secretVersion` is not available |
| `resource_digest_mismatch` | Content fetched at `args.resource` does not match the attested digest |
| `credential_not_found` | The credential referenced by `credentialRef` does not exist in `wrappedCredentials` |
| `credential_ambiguous` | `credentialRef` omitted but `wrappedCredentials` has multiple entries |
| `credential_decryption_failed` | The wrapped credential could not be decrypted |
| `attestation_required` | Server requires attestation but none was provided |

Attestation errors do not introduce new JSON-RPC error codes. All failures are communicated as tool execution errors (`isError: true`), which is consistent with how MCP handles policy rejection and security check failures.

### Acknowledgement Protocol Endpoint

The `_ack` endpoint at `{iss}/_ack` is reserved for future registration. See Security Implications — Acknowledgement Protocol.

## Open Questions

### Normative

- **Asymmetric key discovery**: For ES256/RS256 mode, how should the verifier discover the issuer's public key? Options include: well-known URL under the `iss` domain, a DHT-based key registry, or out-of-band distribution. This SEP leaves key discovery unspecified for now and expects a follow-up SEP or extension to standardize discovery.
- **JSON Schema**: Should the attestation envelope be defined as a formal JSON Schema in addition to the TypeScript interface? A JSON Schema would improve cross-language portability for conformance testing.
- **Nonce cache operational guidance**: Should the spec recommend concrete bloom filter parameters (e.g., 1M entry capacity, 0.1% FP rate, 300s eviction) or leave cache sizing to implementation?
- **Conformance test suite location**: Should the attestation conformance tests live in the MCP conformance repository or in the reference implementation's repository?
- **`serverFingerprint` format**: Should the spec define a standard format for the server fingerprint (e.g., `sha256$<hex>` of the server's public key or TLS certificate), or leave it as an opaque string defined by each deployment?

### Non-Normative

- **EU AI Act compliance mapping**: A companion document mapping each field of the attestation envelope to specific requirements in EU AI Act Articles 12, 13, 14, and 26(6) would aid enterprise procurement teams. Should this be included as an appendix or published separately?
- **Privacy classification of `serverFingerprint`**: The fingerprint identifies which MCP server received the call, which may be PII-adjacent or commercially sensitive in some deployments. Should the spec include a privacy consideration for this field, or is it out of scope?
- **Acknowledgement protocol specification**: The `_ack` reserved key is described briefly in the wrappedCredentials section. Should a future extension define a full acknowledgement protocol (endpoint discovery, retry, timeout, error codes) as a separate SEP?
