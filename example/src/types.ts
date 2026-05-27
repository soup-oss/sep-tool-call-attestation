/** Matches the SEP-2787 Attestation interface from the spec */
export interface ToolCallEntry {
  name: string;
  args_ref?: { uri: string; digest: string };
  args_projection?: string;
  serverFingerprint: string;
}

export interface Attestation {
  version: 1;
  alg: "HS256" | "ES256" | "RS256";
  iss: string;
  sub: string;
  secretVersion: string;
  iat: string;
  exp: number;
  nonce: string;
  intent: string;
  toolCalls: ToolCallEntry[];
  signature: string;
}

export type Alg = Attestation["alg"];

export interface VerifyParams {
  envelope: Attestation;
  secret: string;
  runtimeToolName: string;
  runtimeArguments: Record<string, unknown>;
  runtimeServerFingerprint: string;
  now?: Date;
  resolveRef?: (uri: string) => Promise<Uint8Array>;
  nonceCache?: Set<string>;
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  projectionMatch?: "identity" | "redacted" | null;
}
