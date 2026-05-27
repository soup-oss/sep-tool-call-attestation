/**
 * RFC 8785 (JCS) canonicalization — sorted keys, no whitespace.
 * Built-in JSON.stringify satisfies the spec for our data: no
 * ES6 Map ordering quirks, numbers within safe integer range,
 * strings with standard escaping.
 */
export function canonicalize(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const items = obj.map(canonicalize);
    return "[" + items.join(",") + "]";
  }

  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const pairs = keys.map(
    (k) => JSON.stringify(k) + ":" + canonicalize((obj as Record<string, unknown>)[k]),
  );
  return "{" + pairs.join(",") + "}";
}
