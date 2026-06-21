/** Matches the SEP-2787 Attestation interface from the spec */
export interface ToolCallEntry {
  name: string;
  argsRef?: { uri: string; digest: string };
  argsProjection?: string;
  serverFingerprint: string;
}

export interface Attestation {
  issuerAsserted: {
    alg: "HS256" | "ES256" | "RS256";
    iss: string;
    sub: string;
    secretVersion: string;
    iat: string;
    expSeconds: number;
    nonce: string;
  };
  plannerDeclared: {
    intent: string;
    requestedCapability?: string;
    sessionId?: string;
    turnId?: string;
    toolCallId?: string;
    agentLineage?: string;
  };
  payloadDerived: {
    toolCalls: ToolCallEntry[];
  };
  signature: string;
}

export type Alg = Attestation["issuerAsserted"]["alg"];

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
