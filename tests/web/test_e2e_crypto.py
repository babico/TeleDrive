"""Client-side E2E encryption: teledrive-crypto.js round-trip tests.

The crypto module is browser code (WebCrypto), verified here through
Node's identical crypto.subtle implementation: encryption round-trips,
wrong passphrases and tampered bytes fail closed, and the self-
describing header parses exactly as specified.
"""
import shutil
import subprocess
import textwrap

import pytest

NODE = shutil.which("node")

SCRIPT = textwrap.dedent("""
    const fs = require('fs');
    const vm = require('vm');
    const code = fs.readFileSync(process.argv[1], 'utf8');
    const sandbox = {console, TextEncoder, URL, setTimeout,
                     crypto: require('crypto').webcrypto};
    vm.createContext(sandbox);
    vm.runInContext(code, sandbox);
    const TC = sandbox.TeledriveCrypto;
    const enc = new TextEncoder();

    async function fail(msg){ throw new Error(msg); }

    (async () => {
      // Header sanity.
      if (TC.MAGIC !== 'TDENC1' || TC.HEADER_LEN !== 39) fail('bad constants');

      // Round-trip with the real default iteration count.
      const plain = enc.encode('TeleDrive E2E round-trip payload 📦');
      const blob = await TC.encryptBytes('correct horse battery', plain);
      if (!TC.isEncrypted(blob)) fail('blob not detected as encrypted');
      if (blob.length !== TC.HEADER_LEN + plain.length + 16)
        fail('unexpected blob length: ' + blob.length);
      const back = await TC.decryptBytes('correct horse battery', blob);
      if (Buffer.from(back).compare(Buffer.from(plain)) !== 0)
        fail('round-trip mismatch');

      // Per-encryption randomness: two encryptions of the same bytes
      // with the same passphrase differ (fresh salt + IV).
      const blob2 = await TC.encryptBytes('correct horse battery', plain);
      if (Buffer.from(blob).compare(Buffer.from(blob2)) === 0)
        fail('identical ciphertexts — salt/IV reuse');

      // Wrong passphrase fails closed.
      try { await TC.decryptBytes('wrong passphrase', blob); fail('wrong passphrase accepted'); }
      catch (e) { if (!/wrong passphrase|corrupted/.test(e.message)) throw e; }

      // Tampered ciphertext fails closed (GCM authentication).
      const tampered = Uint8Array.from(blob);
      tampered[tampered.length - 1] ^= 0x01;
      try { await TC.decryptBytes('correct horse battery', tampered); fail('tampered blob accepted'); }
      catch (e) { if (!/wrong passphrase|corrupted/.test(e.message)) throw e; }

      // Non-encrypted input is rejected by decryptBytes and undetected
      // by isEncrypted.
      if (TC.isEncrypted(plain)) fail('plaintext detected as encrypted');
      try { await TC.decryptBytes('x', plain); fail('plaintext accepted'); }
      catch (e) { if (!/Not a TeleDrive-encrypted blob/.test(e.message)) throw e; }

      // Custom iteration counts round-trip through the header.
      const fast = await TC.encryptBytes('pin', enc.encode('abc'), 1000);
      let ok = false;
      try { await TC.decryptBytes('pin', fast); ok = true; } catch (e) {}
      if (!ok) fail('custom iteration count failed');
      const dv = new DataView(fast.buffer, fast.byteOffset, fast.byteLength);
      if (dv.getUint32(7, false) !== 1000) fail('iterations not stored in header');

      // Empty input requires a passphrase.
      try { await TC.encryptBytes('', plain); fail('empty passphrase accepted'); }
      catch (e) { if (!/passphrase/.test(e.message)) throw e; }

      console.log('NODE_CRYPTO_OK');
    })().catch((e) => { console.error('FAIL: ' + e.message); process.exit(1); });
""")


@pytest.mark.skipif(NODE is None, reason="node is required")
def test_teledrive_crypto_round_trip():
    result = subprocess.run(
        [NODE, "-e", SCRIPT, "web/static/teledrive-crypto.js"],
        capture_output=True, text=True, timeout=120, cwd=".",
    )
    assert result.returncode == 0, result.stderr
    assert "NODE_CRYPTO_OK" in result.stdout
