/**
 * TOTP utilities — RFC 6238 (HMAC-SHA1, 30s step, 6 digits).
 *
 * Pure Web Crypto, no deps, no network. Used by:
 *  - InitWizard: verify the authenticator was provisioned correctly
 *  - UnlockDialog: prove the operator has live access to the authenticator
 *
 * The TOTP secret bytes never leave the renderer process.
 */

export async function generateTotp(
  secretBytes: Uint8Array,
  timestampSec: number,
): Promise<string> {
  const counter = Math.floor(timestampSec / 30);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // 64-bit big-endian counter. High 32 bits stay 0 for any realistic Unix timestamp.
  view.setUint32(4, counter, false);

  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes as BufferSource,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));
  const offset = (sig[sig.length - 1] ?? 0) & 0xf;
  const code =
    (((sig[offset] ?? 0) & 0x7f) << 24) |
    ((sig[offset + 1] ?? 0) << 16) |
    ((sig[offset + 2] ?? 0) << 8) |
    (sig[offset + 3] ?? 0);
  return (code % 1_000_000).toString().padStart(6, '0');
}

/**
 * Verify a 6-digit code against the secret with ±1 step skew (RFC 6238 §5.2).
 * Returns true when the code matches t-30s, t, or t+30s.
 */
export async function verifyTotp(
  secretBytes: Uint8Array,
  userCode: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  const trimmed = userCode.trim();
  if (!/^\d{6}$/.test(trimmed)) return false;
  const [prev, curr, next] = await Promise.all([
    generateTotp(secretBytes, nowSec - 30),
    generateTotp(secretBytes, nowSec),
    generateTotp(secretBytes, nowSec + 30),
  ]);
  return trimmed === prev || trimmed === curr || trimmed === next;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

/**
 * RFC 4648 Base32 decoder. Used to accept TOTP secrets in the same
 * format as the QR provisioning URI (`?secret=<base32>`) and as the
 * "Show secret" pane of most authenticator apps. Padding `=` is
 * tolerated. Whitespace and case ignored.
 */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32ToBytes(s: string): Uint8Array {
  const cleaned = s.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of cleaned) {
    const idx = B32_ALPHABET.indexOf(c);
    if (idx < 0) throw new Error(`invalid base32 character: ${c}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/**
 * Parse a TOTP secret given as either:
 *   - hex (40 chars / 20 bytes), Studio's wizard format, or
 *   - base32 (32 chars / 20 bytes, RFC 4648), the format used by the
 *     QR provisioning URI and shown by every authenticator app.
 *
 * Format is detected by alphabet:
 *   - all chars in [0-9a-fA-F] → hex
 *   - all chars in [A-Z2-7] (case-insensitive) → base32
 *   - otherwise → null
 *
 * Returns null on any parse failure. Caller surfaces the error.
 */
export function parseSecret(input: string): Uint8Array | null {
  const trimmed = input.replace(/\s+/g, '').replace(/=+$/, '');
  if (trimmed.length === 0) return null;

  // Hex path: digits + a-f only, even length, ≥ 16 bytes.
  if (/^[0-9a-fA-F]+$/.test(trimmed)) {
    if (trimmed.length % 2 !== 0) return null;
    if (trimmed.length < 32) return null;
    try {
      return hexToBytes(trimmed);
    } catch {
      return null;
    }
  }

  // Base32 path: A-Z + 2-7 (case-insensitive). Length 32 → 20 bytes.
  if (/^[A-Za-z2-7]+$/.test(trimmed)) {
    try {
      const bytes = base32ToBytes(trimmed);
      if (bytes.length < 16) return null;
      return bytes;
    } catch {
      return null;
    }
  }

  return null;
}
