/* TeleDrive client-side E2E encryption (zero-knowledge).
 *
 * Files are encrypted in the browser with WebCrypto AES-256-GCM before
 * they are uploaded; the server only ever sees an opaque blob. The key
 * is derived from the user's passphrase with PBKDF2-SHA256 and never
 * leaves the browser — losing the passphrase means losing the data.
 *
 * Blob layout (self-describing, version 1):
 *   offset 0   magic "TDENC1"            (6 bytes)
 *   offset 6   format version = 1        (1 byte)
 *   offset 7   PBKDF2 iterations, u32 BE (4 bytes)
 *   offset 11  PBKDF2 salt               (16 bytes)
 *   offset 27  AES-GCM IV                (12 bytes)
 *   offset 39  ciphertext + GCM tag      (rest)
 *
 * Exposed as window.TeledriveCrypto; every function is async and
 * throws on tampering, wrong passphrases or unsupported formats.
 */
(function (global) {
  "use strict";

  const MAGIC = "TDENC1";
  const MAGIC_BYTES = new Uint8Array([0x54, 0x44, 0x45, 0x4e, 0x43, 0x31]);
  const VERSION = 1;
  const HEADER_LEN = 39;
  const DEFAULT_ITERATIONS = 310000;
  const SALT_LEN = 16;
  const IV_LEN = 12;

  const subtle = () => {
    const c = global.crypto && global.crypto.subtle;
    if (!c) throw new Error("WebCrypto is unavailable in this browser");
    return c;
  };

  const randomBytes = (n) => {
    const out = new Uint8Array(n);
    if (global.crypto && global.crypto.getRandomValues) {
      global.crypto.getRandomValues(out);
    } else {
      throw new Error("Secure randomness is unavailable");
    }
    return out;
  };

  const isBytes = (b) => !!b && ArrayBuffer.isView(b)
    && !(b instanceof DataView);

  const isEncrypted = (bytes) => {
    if (!isBytes(bytes) || bytes.length < HEADER_LEN) return false;
    for (let i = 0; i < MAGIC_BYTES.length; i++) {
      if (bytes[i] !== MAGIC_BYTES[i]) return false;
    }
    return true;
  };

  const deriveKey = async (passphrase, salt, iterations) => {
    const enc = new TextEncoder();
    const material = await subtle().importKey(
      "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return subtle().deriveKey(
      {name: "PBKDF2", salt: salt, iterations: iterations,
       hash: "SHA-256"},
      material,
      {name: "AES-GCM", length: 256},
      false,           // not extractable: the raw key never exists outside derive
      ["encrypt", "decrypt"]);
  };

  const encryptBytes = async (passphrase, bytes,
                              iterations = DEFAULT_ITERATIONS) => {
    if (typeof passphrase !== "string" || !passphrase) {
      throw new Error("A passphrase is required");
    }
    if (!isBytes(bytes)) {
      throw new Error("encryptBytes expects a Uint8Array");
    }
    const salt = randomBytes(SALT_LEN);
    const iv = randomBytes(IV_LEN);
    const key = await deriveKey(passphrase, salt, iterations);
    const ciphertext = new Uint8Array(
      await subtle().encrypt({name: "AES-GCM", iv: iv}, key, bytes));
    const blob = new Uint8Array(HEADER_LEN + ciphertext.length);
    blob.set(MAGIC_BYTES, 0);
    blob[6] = VERSION;
    new DataView(blob.buffer).setUint32(7, iterations, false);
    blob.set(salt, 11);
    blob.set(iv, 27);
    blob.set(ciphertext, HEADER_LEN);
    return blob;
  };

  const decryptBytes = async (passphrase, blob) => {
    if (!isEncrypted(blob)) {
      throw new Error("Not a TeleDrive-encrypted blob");
    }
    const version = blob[6];
    if (version !== VERSION) {
      throw new Error("Unsupported encryption format version " + version);
    }
    const iterations = new DataView(
      blob.buffer, blob.byteOffset, blob.byteLength).getUint32(7, false);
    if (iterations < 1 || iterations > 10_000_000) {
      throw new Error("Invalid PBKDF2 iteration count");
    }
    const salt = blob.slice(11, 11 + SALT_LEN);
    const iv = blob.slice(27, 27 + IV_LEN);
    const ciphertext = blob.slice(HEADER_LEN);
    const key = await deriveKey(passphrase, salt, iterations);
    try {
      return new Uint8Array(await subtle().decrypt(
        {name: "AES-GCM", iv: iv}, key, ciphertext));
    } catch (exc) {
      throw new Error(
        "Decryption failed — wrong passphrase or corrupted data");
    }
  };

  global.TeledriveCrypto = {
    MAGIC: MAGIC,
    VERSION: VERSION,
    HEADER_LEN: HEADER_LEN,
    DEFAULT_ITERATIONS: DEFAULT_ITERATIONS,
    isEncrypted: isEncrypted,
    deriveKey: deriveKey,
    encryptBytes: encryptBytes,
    decryptBytes: decryptBytes,
  };
})(typeof window !== "undefined" ? window : globalThis);
