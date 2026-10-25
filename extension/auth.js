// Role-separated HMAC proofs bind both peers to fresh nonces. No token on the wire.
export function nonce() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, "0")).join("");
}
export function validNonce(value) { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
export async function proof(token, role, serverNonce, clientNonce) {
  return sign(token, `ccb-v1:${role}:${serverNonce}:${clientNonce}`);
}
export async function frameProof(token, role, serverNonce, clientNonce, seq, payload) {
  return sign(token, `ccb-v1:message:${role}:${serverNonce}:${clientNonce}:${seq}:${payload}`);
}
async function sign(token, message) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(token), {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  const result = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(result), b => b.toString(16).padStart(2, "0")).join("");
}
export function equalProof(a, b) {
  if (!validNonce(a) || !validNonce(b)) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
