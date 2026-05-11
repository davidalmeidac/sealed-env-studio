import { useState, useEffect } from 'react';
import type { SealedMode, DecryptVaultResponse } from '../lib/types';
import { decryptVault, mintUnsealToken } from '../lib/workspace';
import { readLocalEnv } from '../lib/init';
import { hasVaultCredentials, loadVaultCredentials } from '../lib/credstore';
import { parseSecret, verifyTotp, hexToBytes, bytesToHex } from '../lib/totp';

/**
 * Normalize whatever the operator typed (hex or base32) into the hex
 * format the Rust backend expects. Returns null if input is invalid;
 * caller should have already validated via parseSecret().
 */
function secretAsHex(input: string): string | null {
  const bytes = parseSecret(input);
  return bytes ? bytesToHex(bytes) : null;
}

interface Props {
  path: string;
  mode: SealedMode;
  rawContent: string;
  onUnlocked: (result: DecryptVaultResponse) => void;
  onCancel: () => void;
}

interface FieldErrors {
  masterKey?: string;
  signingKey?: string;
  totpSecret?: string;
  authCode?: string;
  passphrase?: string;
  unsealToken?: string;
  mint?: string;
  generic?: string;
}

export function UnlockDialog({ path, mode, rawContent, onUnlocked, onCancel }: Props) {
  // ─── Raw-keys mode state ──────────────────────────────────────────────────
  const [masterKey, setMasterKey] = useState('');
  const [signingKey, setSigningKey] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [unsealToken, setUnsealToken] = useState('');
  const [showAdvancedToken, setShowAdvancedToken] = useState(false);
  const [mintedToken, setMintedToken] = useState<string | null>(null);
  const [mintedExp, setMintedExp] = useState<number | null>(null);
  // Legacy `.env.local` compat — read-only autoload for users coming from the
  // CLI flow. Studio NEVER writes `.env.local` (SEC-010) but reading is opt-in
  // backward compat. Tracks which fields actually came from the legacy file
  // so the UI can warn + offer a clear-and-paste-manually escape hatch.
  const [legacyAutoload, setLegacyAutoload] = useState<Set<'master' | 'signing' | 'totp' | 'token'>>(
    () => new Set(),
  );

  // ─── Stored-creds (Tier A) mode state ─────────────────────────────────────
  const [credsAvailable, setCredsAvailable] = useState(false);
  const [useStoredCreds, setUseStoredCreds] = useState(false);
  const [passphrase, setPassphrase] = useState('');

  // ─── Shared state ─────────────────────────────────────────────────────────
  const [authCode, setAuthCode] = useState('');
  const [errors, setErrors] = useState<FieldErrors>({});
  const [busy, setBusy] = useState(false);
  const [minting, setMinting] = useState(false);

  const needsSigning = mode === 'team' || mode === 'enterprise';
  const needsTotp = mode === 'enterprise';

  const filename = path.replace(/\\/g, '/').split('/').pop() ?? path;
  const folderPath = (() => {
    const norm = path.replace(/\\/g, '/');
    const idx = norm.lastIndexOf('/');
    return idx === -1 ? '' : norm.slice(0, idx);
  })();

  // Probe the OS keychain on mount. If creds exist, default to passphrase mode.
  useEffect(() => {
    let cancelled = false;
    void hasVaultCredentials({ absolutePath: path })
      .then((has) => {
        if (cancelled) return;
        setCredsAvailable(has);
        if (has) setUseStoredCreds(true);
      })
      .catch(() => {
        // Keystore probe failure is non-fatal — fall through to raw mode.
      });
    return () => { cancelled = true; };
  }, [path]);

  // Legacy `.env.local` autoload. Opt-in backward compat with CLI users who
  // have their keys stored next to the vault. Studio never writes that file —
  // the credstore (OS Credential Manager + passphrase) is the recommended
  // path. This effect only PRE-FILLS the raw-mode fields; the operator still
  // sees a banner advising verification before unlocking.
  useEffect(() => {
    if (!folderPath) return;
    let cancelled = false;
    void readLocalEnv({ folderPath }).then((resp) => {
      if (cancelled || !resp.found) return;
      const loaded: typeof legacyAutoload = new Set();
      if (resp.masterKeyHex) { setMasterKey(resp.masterKeyHex); loaded.add('master'); }
      if (resp.signingKeyHex) { setSigningKey(resp.signingKeyHex); loaded.add('signing'); }
      if (resp.totpSecretHex) { setTotpSecret(resp.totpSecretHex); loaded.add('totp'); }
      if (resp.unsealToken) {
        setUnsealToken(resp.unsealToken);
        setShowAdvancedToken(true);
        loaded.add('token');
      }
      if (loaded.size > 0) setLegacyAutoload(loaded);
    }).catch(() => {
      // Opportunistic — never blocks unlock.
    });
    return () => { cancelled = true; };
  }, [folderPath]);

  const clearFieldError = (key: keyof FieldErrors) => {
    setErrors((prev) => {
      const next = { ...prev };
      delete next[key];
      return next;
    });
  };

  const switchToRawMode = () => {
    setUseStoredCreds(false);
    setPassphrase('');
    setErrors({});
  };

  const switchToStoredMode = () => {
    setUseStoredCreds(true);
    setMasterKey('');
    setSigningKey('');
    setTotpSecret('');
    setUnsealToken('');
    setShowAdvancedToken(false);
    setLegacyAutoload(new Set());
    setErrors({});
  };

  /** Verify the 6-digit authenticator code against an arbitrary TOTP secret. */
  const verifyAuthCodeAgainst = async (totpSecretHex: string): Promise<boolean> => {
    const ok = await verifyTotp(hexToBytes(totpSecretHex), authCode);
    if (!ok) {
      setErrors((prev) => ({
        ...prev,
        authCode: "Code doesn't match. Wait for the next 30-second window.",
      }));
    }
    return ok;
  };

  // ═════════════════════════════════════════════════════════════════════════
  // Stored-creds unlock flow (Tier A)
  // ═════════════════════════════════════════════════════════════════════════

  const handleUnlockFromKeystore = async () => {
    const e: FieldErrors = {};
    if (!passphrase) e.passphrase = 'Passphrase is required';
    if (needsTotp) {
      if (!authCode.trim()) e.authCode = '6-digit code is required';
      else if (!/^\d{6}$/.test(authCode.trim())) e.authCode = 'Must be 6 digits';
    }
    if (Object.keys(e).length > 0) {
      setErrors(e);
      return;
    }

    setBusy(true);
    setErrors({});

    try {
      const creds = await loadVaultCredentials({ absolutePath: path, passphrase });

      // Enterprise: verify the live 6-digit code against the unwrapped TOTP secret.
      if (needsTotp) {
        if (!creds.totp) {
          setErrors({
            generic: 'Stored credentials are missing the TOTP secret. Re-save with all keys.',
          });
          setBusy(false);
          return;
        }
        const ok = await verifyAuthCodeAgainst(creds.totp);
        if (!ok) {
          setBusy(false);
          return;
        }
      }

      const result = await decryptVault({
        rawContent,
        masterKeyHex: creds.master,
        ...(creds.signing ? { signingKeyHex: creds.signing } : {}),
        ...(creds.totp ? { totpSecretHex: creds.totp } : {}),
      });
      onUnlocked(result);
    } catch {
      // The Rust side collapses bad passphrase / tampered blob / wrong vault_id
      // into DecryptFailed; we surface a single message to avoid leaking which case.
      setErrors({
        generic: 'Could not unlock with that passphrase. Try again or use raw keys.',
      });
    } finally {
      setBusy(false);
    }
  };

  // ═════════════════════════════════════════════════════════════════════════
  // Raw-keys unlock flow (existing — bootstrap, recovery, CLI interop)
  // ═════════════════════════════════════════════════════════════════════════

  /** Verify the 6-digit authenticator code against the typed TOTP secret. */
  const verifyAuthCodeFromTyped = async (): Promise<boolean> => {
    const secretBytes = parseSecret(totpSecret);
    if (!secretBytes) {
      setErrors((prev) => ({
        ...prev,
        totpSecret: 'TOTP secret must be 40 hex chars or 32 base32 chars',
      }));
      return false;
    }
    const ok = await verifyTotp(secretBytes, authCode);
    if (!ok) {
      setErrors((prev) => ({
        ...prev,
        authCode: "Code doesn't match. Wait for the next 30-second window.",
      }));
    }
    return ok;
  };

  const handleUnlockFromRaw = async () => {
    const e: FieldErrors = {};
    if (!masterKey.trim()) e.masterKey = 'Master key is required';
    if (needsSigning && !signingKey.trim()) e.signingKey = 'Signing key is required';

    if (needsTotp) {
      if (showAdvancedToken) {
        if (!unsealToken.trim()) e.unsealToken = 'Unseal token is required';
      } else {
        if (!totpSecret.trim()) {
          e.totpSecret = 'TOTP secret is required';
        } else if (parseSecret(totpSecret) === null) {
          e.totpSecret =
            'Must be 40 hex characters or 32 base32 characters (A-Z, 2-7)';
        }
      }
    }

    if (Object.keys(e).length > 0) {
      setErrors(e);
      return;
    }

    setBusy(true);
    setErrors({});

    try {
      const result = await decryptVault({
        rawContent,
        masterKeyHex: masterKey.trim(),
        ...(needsSigning && signingKey.trim()
          ? { signingKeyHex: signingKey.trim() }
          : {}),
        ...(needsTotp && showAdvancedToken && unsealToken.trim()
          ? { unsealToken: unsealToken.trim() }
          : {}),
        ...(needsTotp && !showAdvancedToken && totpSecret.trim()
          ? (() => {
              const hex = secretAsHex(totpSecret);
              return hex ? { totpSecretHex: hex } : {};
            })()
          : {}),
      });
      onUnlocked(result);
    } catch {
      setErrors({ generic: 'Could not decrypt vault. Check your keys and try again.' });
    } finally {
      setBusy(false);
    }
  };

  const handleMintToken = async () => {
    const e: FieldErrors = {};
    if (!masterKey.trim()) e.masterKey = 'Master key is required';
    if (!totpSecret.trim()) e.totpSecret = 'TOTP secret is required';
    if (!authCode.trim()) e.authCode = '6-digit code is required to mint a token';
    if (Object.keys(e).length > 0) {
      setErrors((prev) => ({ ...prev, ...e }));
      return;
    }

    const ok = await verifyAuthCodeFromTyped();
    if (!ok) return;

    setMinting(true);
    setErrors((prev) => { const n = { ...prev }; delete n.mint; return n; });

    try {
      const hex = secretAsHex(totpSecret);
      if (!hex) {
        setErrors((prev) => ({ ...prev, totpSecret: 'TOTP secret format invalid' }));
        setMinting(false);
        return;
      }
      const resp = await mintUnsealToken({
        rawContent,
        masterKeyHex: masterKey.trim(),
        totpSecretHex: hex,
        ttlSeconds: 60,
      });
      setMintedToken(resp.unsealToken);
      setMintedExp(resp.expUnix);
    } catch {
      setErrors((prev) => ({
        ...prev,
        mint: 'Could not mint token. Check the master key and TOTP secret.',
      }));
    } finally {
      setMinting(false);
    }
  };

  const copyToken = async () => {
    if (!mintedToken) return;
    try { await navigator.clipboard.writeText(mintedToken); } catch { /* ignore */ }
  };

  const expSecondsRemaining = mintedExp
    ? Math.max(0, mintedExp - Math.floor(Date.now() / 1000))
    : 0;

  const handleSubmit = useStoredCreds ? handleUnlockFromKeystore : handleUnlockFromRaw;

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Unlock vault">
      <div className="modal">
        <div className="modal__header">
          <h2 className="modal__title">Unlock vault</h2>
          <button
            className="btn btn--ghost btn--icon modal__close"
            onClick={onCancel}
            aria-label="Close"
            disabled={busy}
          >
            ×
          </button>
        </div>

        <div className="modal__body">
          <p className="unlock-dialog__path">
            <span className="filename">{filename}</span>
            {' · '}
            <span className={`mode-badge mode-badge--${mode}`}>
              {mode.charAt(0).toUpperCase() + mode.slice(1)}
            </span>
          </p>

          {errors.generic && (
            <div className="field-error field-error--banner">{errors.generic}</div>
          )}

          {useStoredCreds ? (
            /* ═════════════════════════════════════════════════════════
               TIER A — Passphrase unlock from OS keychain
               ═════════════════════════════════════════════════════════ */
            <>
              <p className="unlock-dialog__autoload-note">
                Saved in system credential manager. Enter your passphrase to unlock.
              </p>

              <label className="settings-group__field">
                <span>Passphrase</span>
                <input
                  type="password"
                  placeholder="Your vault passphrase"
                  value={passphrase}
                  onChange={(e) => { setPassphrase(e.target.value); clearFieldError('passphrase'); }}
                  autoFocus
                  disabled={busy}
                  className={errors.passphrase ? 'input--error' : ''}
                />
                {errors.passphrase && (
                  <span className="field-error">{errors.passphrase}</span>
                )}
              </label>

              {needsTotp && (
                <label className="settings-group__field">
                  <span>Authenticator code (6 digits)</span>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    autoComplete="one-time-code"
                    placeholder="••••••"
                    value={authCode}
                    onChange={(e) => {
                      setAuthCode(e.target.value.replace(/\s/g, ''));
                      clearFieldError('authCode');
                    }}
                    disabled={busy}
                    className={`unlock-dialog__otp-input${errors.authCode ? ' input--error' : ''}`}
                  />
                  {errors.authCode && (
                    <span className="field-error">{errors.authCode}</span>
                  )}
                  <span className="unlock-dialog__hint">
                    Open your authenticator and enter the current code.
                  </span>
                </label>
              )}

              <button
                type="button"
                className="unlock-dialog__advanced-toggle"
                onClick={switchToRawMode}
              >
                Forgot passphrase? Use raw keys instead →
              </button>
            </>
          ) : (
            /* ═════════════════════════════════════════════════════════
               RAW KEYS — Bootstrap / recovery / CLI interop
               ═════════════════════════════════════════════════════════ */
            <>
              {credsAvailable && (
                <p className="unlock-dialog__autoload-note">
                  Credentials exist in the system credential manager.{' '}
                  <button
                    type="button"
                    className="unlock-dialog__autoload-clear"
                    onClick={switchToStoredMode}
                  >
                    Use the passphrase instead
                  </button>
                </p>
              )}

              {legacyAutoload.size > 0 && (
                <p className="unlock-dialog__autoload-note">
                  Found legacy <code>.env.local</code>. Verify these match your vault before unlocking.{' '}
                  <button
                    type="button"
                    className="unlock-dialog__autoload-clear"
                    onClick={() => {
                      if (legacyAutoload.has('master')) setMasterKey('');
                      if (legacyAutoload.has('signing')) setSigningKey('');
                      if (legacyAutoload.has('totp')) setTotpSecret('');
                      if (legacyAutoload.has('token')) {
                        setUnsealToken('');
                        setShowAdvancedToken(false);
                      }
                      setLegacyAutoload(new Set());
                    }}
                  >
                    Clear and paste manually
                  </button>
                </p>
              )}

              <label className="settings-group__field">
                <span>Master key (hex)</span>
                <input
                  type="password"
                  placeholder="64 hex characters"
                  value={masterKey}
                  onChange={(e) => { setMasterKey(e.target.value); clearFieldError('masterKey'); }}
                  autoFocus
                  disabled={busy}
                  className={errors.masterKey ? 'input--error' : ''}
                />
                {errors.masterKey && (
                  <span className="field-error">{errors.masterKey}</span>
                )}
              </label>

              {needsSigning && (
                <label className="settings-group__field">
                  <span>Signing key (hex)</span>
                  <input
                    type="password"
                    placeholder="64 hex characters"
                    value={signingKey}
                    onChange={(e) => { setSigningKey(e.target.value); clearFieldError('signingKey'); }}
                    disabled={busy}
                    className={errors.signingKey ? 'input--error' : ''}
                  />
                  {errors.signingKey && (
                    <span className="field-error">{errors.signingKey}</span>
                  )}
                </label>
              )}

              {needsTotp && !showAdvancedToken && (
                <>
                  <label className="settings-group__field">
                    <span>TOTP secret</span>
                    <input
                      type="password"
                      placeholder="hex (40 chars) or base32 (32 chars)"
                      value={totpSecret}
                      onChange={(e) => { setTotpSecret(e.target.value); clearFieldError('totpSecret'); }}
                      disabled={busy}
                      className={errors.totpSecret ? 'input--error' : ''}
                    />
                    {errors.totpSecret && (
                      <span className="field-error">{errors.totpSecret}</span>
                    )}
                    <span className="unlock-dialog__hint">
                      Paste from your password manager backup. After this unlock,
                      save to the system credential manager so future unlocks only
                      need a passphrase plus 6-digit code.
                    </span>
                  </label>

                  <button
                    type="button"
                    className="unlock-dialog__advanced-toggle"
                    onClick={() => {
                      setShowAdvancedToken(true);
                      setAuthCode('');
                      setTotpSecret('');
                      clearFieldError('authCode');
                      clearFieldError('totpSecret');
                    }}
                  >
                    Use a pre-built unseal token
                  </button>
                </>
              )}

              {needsTotp && showAdvancedToken && (
                <>
                  <label className="settings-group__field">
                    <span>Unseal token</span>
                    <input
                      type="text"
                      placeholder="usl_…"
                      value={unsealToken}
                      onChange={(e) => { setUnsealToken(e.target.value); clearFieldError('unsealToken'); }}
                      disabled={busy}
                      className={errors.unsealToken ? 'input--error' : ''}
                    />
                    {errors.unsealToken && (
                      <span className="field-error">{errors.unsealToken}</span>
                    )}
                  </label>

                  <button
                    type="button"
                    className="unlock-dialog__advanced-toggle"
                    onClick={() => {
                      setShowAdvancedToken(false);
                      setUnsealToken('');
                      clearFieldError('unsealToken');
                    }}
                  >
                    ← Use a 6-digit authenticator code instead
                  </button>
                </>
              )}

              {needsTotp && !showAdvancedToken && (
                <div className="unlock-dialog__mint">
                  <label className="settings-group__field">
                    <span>Authenticator code (for token mint)</span>
                    <input
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]{6}"
                      maxLength={6}
                      autoComplete="one-time-code"
                      placeholder="••••••"
                      value={authCode}
                      onChange={(e) => {
                        setAuthCode(e.target.value.replace(/\s/g, ''));
                        clearFieldError('authCode');
                      }}
                      disabled={busy || minting}
                      className={`unlock-dialog__otp-input${errors.authCode ? ' input--error' : ''}`}
                    />
                    {errors.authCode && (
                      <span className="field-error">{errors.authCode}</span>
                    )}
                    <span className="unlock-dialog__hint">
                      Required only when generating a token for sharing.
                      The unlock above uses the TOTP secret alone.
                    </span>
                  </label>

                  <button
                    type="button"
                    className="btn btn--ghost btn--small"
                    onClick={() => { void handleMintToken(); }}
                    disabled={minting || busy}
                  >
                    {minting ? 'Minting…' : 'Generate unseal token (for sharing)'}
                  </button>

                  {errors.mint && (
                    <span className="field-error">{errors.mint}</span>
                  )}

                  {mintedToken && (
                    <div className="unlock-dialog__minted">
                      <div className="unlock-dialog__minted-header">
                        <span className="unlock-dialog__minted-label">
                          Token minted · expires in {expSecondsRemaining}s
                        </span>
                        <button
                          type="button"
                          className="btn btn--ghost btn--small"
                          onClick={() => { void copyToken(); }}
                        >
                          Copy
                        </button>
                      </div>
                      <textarea
                        className="unlock-dialog__minted-text"
                        value={mintedToken}
                        readOnly
                        rows={3}
                      />
                      <p className="unlock-dialog__minted-hint">
                        Paste this into a CI/CD form or share with a remote operator.
                        The token is single-use and expires in 60 seconds.
                      </p>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        <div className="modal__footer">
          <button className="btn btn--ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            onClick={() => { void handleSubmit(); }}
            disabled={busy}
          >
            {busy ? 'Unlocking…' : 'Unlock'}
          </button>
        </div>
      </div>
    </div>
  );
}
