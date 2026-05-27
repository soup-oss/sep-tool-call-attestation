import { createHmac } from "node:crypto";
import { canonicalize } from "./canonicalize.js";
import type { Attestation } from "./types.js";

type SignInput = Attestation & { signature?: string };

export async function sign(input: SignInput, secret: string): Promise<Attestation> {
  if (input.alg !== "HS256") {
    throw new Error(`Unsupported algorithm: ${input.alg}`);
  }

  const { signature: _, ...fields } = input;
  const payload = { ...fields, signature: "" };

  const canonical = canonicalize(payload);
  const sig = createHmac("sha256", secret).update(canonical).digest("hex");

  return { ...fields, signature: sig };
}
