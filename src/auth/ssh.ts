import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

export type SshVerifyResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Verify an SSH signature against an allowed_signers file.
 *
 * Uses `ssh-keygen -Y verify` — works with any key type stored on any hardware
 * security key (YubiKey, Nitrokey, Google Titan, etc.) or software key.
 *
 * The message signed by the client must be exactly: "praxis-aegis:<nonce>"
 *
 * @param allowedSignersPath  Path to the openssh allowed_signers file for this identity
 * @param identity            The identity string (must appear in allowed_signers file)
 * @param nonce               The challenge nonce that was signed
 * @param signatureB64        Base64-encoded SSH signature (output of `ssh-keygen -Y sign`)
 */
export async function verifySshSignature(
  allowedSignersPath: string,
  identity: string,
  nonce: string,
  signatureB64: string
): Promise<SshVerifyResult> {
  if (!fs.existsSync(allowedSignersPath)) {
    return { ok: false, reason: `No allowed_signers file for identity "${identity}"` };
  }

  const message = `praxis-aegis:${nonce}`;

  // Write signature to a temp file (ssh-keygen -Y verify reads it from disk)
  const tmpDir = os.tmpdir();
  const sigFile = path.join(tmpDir, `aegis-sig-${crypto.randomBytes(8).toString("hex")}.sig`);

  try {
    const sigBuffer = Buffer.from(signatureB64, "base64");
    fs.writeFileSync(sigFile, sigBuffer);

    const result = spawnSync("ssh-keygen", [
      "-Y", "verify",
      "-f", allowedSignersPath,
      "-I", identity,
      "-n", "praxis-aegis",
      "-s", sigFile,
    ], {
      input: message,
      timeout: 5000,
      encoding: "utf8",
    });

    if (result.error) throw result.error;
    if (result.status !== 0) {
      const stderr = (result.stderr ?? "").trim();
      throw Object.assign(new Error("ssh-keygen verify failed"), { stderr });
    }

    return { ok: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const stderr = (err as { stderr?: string }).stderr ?? "";
    return {
      ok: false,
      reason: stderr || msg,
    };
  } finally {
    try { fs.unlinkSync(sigFile); } catch { /* best-effort cleanup */ }
  }
}
