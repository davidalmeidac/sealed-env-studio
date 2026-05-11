import { useState, useEffect } from 'react';
import type { SealedMode, DecryptVaultResponse } from '../lib/types';
import { decryptVault, mintUnsealToken } from '../lib/workspace';
import { readLocalEnv } from '../lib/init';
import { parseSecret, verifyTotp, bytesToHex } from '../lib/totp';

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
  unsealToken?: string;
  mint?: string;
  generic?: string;
}

type Autoloaded = Set<'master' | 'signing' | 'totp' | 'token'>;

export function UnlockDialog({ path, mode, rawContent, onUnlocked, onCancel }: Props) {
  const [masterKey, setMasterKey] = useState('');
  const [signingKey, setSigningKey] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [authCode, setAuthCode] = useState('');
  const [unsealToken, setUnsealToken] = useState('');
  const [showAdvancedToken, setShowAdvancedToken] = useState(false);
  const [showTotpSecretField, setShowTotpSecretField] = useState(false);
  const [mintedToken, setMintedToken] = useState<string | null>(null);
  const [mintedExp, setMintedExp] = useState<number | null>(null);
  const [errors, setErrors] = useState<FieldErrors>({});
  const [busy, setBusy] = useState(false);
  const [minting, setMinting] = useState(false);
  const [autoloaded, setAutoloaded] = useState<Autoloaded>(() => new Set());

  const needsSigning = mode === 'team' || mode === 'enterprise';
  const needsTotp = mode === 'enterprise';

  const filename = path.replace(/\\/g, '/').split('/').pop() ?? path;
  const folderPath = (() => {
    const norm = path.replace(/\\/g, '/');
    const idx = norm.lastIndexOf('/');
    return idx === -1 ? '' : norm.slice(0, idx);
  })();

  // Auto-load credentials from <folder>/.env.local on mount.
  // TOTP secret is loaded silently (not shown in UI — operator types the 6-digit code instead).
  useEffect(() => {
    if (!folderPath) return;
    let cancelled = false;
    void readLocalEnv({ folderPath }).then((resp) => {
      if (cancelled || !resp.found) return;
      const loaded: Autoloaded = new Set();
      if (resp.masterKeyHex) { setMasterKey(resp.masterKeyHex); loaded.add('master'); }
      if (resp.signingKeyHex) { setSigningKey(resp.signingKeyHex); loaded.add('signing'); }
      if (resp.totpSecretHex) { setTotpSecret(resp.totpSecretHex); loaded.add('totp'); }
      if (resp.unsealToken) {
        setUnsealToken(resp.unsealToken);
        setShowAdvancedToken(true);
        loaded.add('token');
      }
      if (loaded.size > 0) setAutoloaded(loaded);
    }).catch(() => {
      // Silent: .env.local autoload is opportunistic, never blocks unlock.
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

  /** Verify the 6-digit authenticator code against the stored TOTP secret (±1 step skew). */
  const verifyAuthCode = async (): Promise<boolean> => {
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

  const handleUnlock = async () => {
    const e: FieldErrors = {};
    if (!masterKey.trim()) e.masterKey = 'Master key is required';
    if (needsSigning && !signingKey.trim()) e.signingKey = 'Signing key is required';

    if (needsTotp) {
      if (showAdvancedToken) {
        if (!unsealToken.trim()) e.unsealToken = 'Unseal token is required';
      } else if (autoloaded.has('totp') && !showTotpSecretField) {
        // Stored-secret path: operator only needs to prove authenticator presence.
        if (!authCode.trim()) e.authCode = '6-digit code is required';
        else if (!/^\d{6}$/.test(authCode.trim())) e.authCode = 'Must be 6 digits';
      } else {
        // Bootstrap / recovery path: operator pastes the secret itself.
        // No 6-digit needed — the secret alone is both proof and minting material.
        // Accepts hex (40 chars) OR base32 (32 chars), the format every
        // authenticator app shows under "manual entry".
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
      // 2FA proof: verify the 6-digit code only when we used that path
      // (stored-secret unlock). Bootstrap/recovery path skips verify
      // because the operator just typed the secret — they already
      // proved possession.
      const usingStoredSecret =
        needsTotp && !showAdvancedToken && autoloaded.has('totp') && !showTotpSecretField;
      if (usingStoredSecret) {
        const ok = await verifyAuthCode();
        if (!ok) {
          setBusy(false);
          return;
        }
      }

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

    // Verify the 6-digit code before minting (same gate as unlock).
    const ok = await verifyAuthCode();
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
    try {
      await navigator.clipboard.writeText(mintedToken);
    } catch {
      // Clipboard may be unavailable in some environments; ignore silently.
    }
  };

  const expSecondsRemaining = mintedExp
    ? Math.max(0, mintedExp - Math.floor(Date.now() / 1000))
    : 0;

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

          {autoloaded.size > 0 && (
            <p className="unlock-dialog__autoload-note">
              Found legacy <code>.env.local</code>. Verify these match your vault.{' '}
              <button
                type="button"
                className="unlock-dialog__autoload-clear"
                onClick={() => {
                  if (autoloaded.has('master')) setMasterKey('');
                  if (autoloaded.has('signing')) setSigningKey('');
                  if (autoloaded.has('totp')) setTotpSecret('');
                  if (autoloaded.has('token')) {
                    setUnsealToken('');
                    setShowAdvancedToken(false);
                  }
                  setAutoloaded(new Set());
                }}
              >
                Clear and paste manually
              </button>
            </p>
          )}

          <label className="settings-group__field">
            <span>
              Master key (hex)            </span>
            <input
              type="password"
              placeholder="64 hex characters"
              value={masterKey}
              onChange={(e) => { setMasterKey(e.target.value); clearFieldError('masterKey'); }}
              autoFocus={!autoloaded.has('master')}
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
              {/*
                Two mutually-exclusive paths:

                 (A) Stored-secret path — `.env.local` has the TOTP
                     secret. The operator just types the 6-digit code
                     from their authenticator. The secret stays on disk;
                     the code is live proof of authenticator possession.

                 (B) Bootstrap / recovery path — no stored secret (first
                     unlock from this machine, or operator clicked
                     "Replace stored secret"). The operator pastes the
                     40-hex secret from their backup. NO 6-digit code is
                     required — typing the secret IS the proof, and we
                     have everything needed to mint the token.
              */}

              {autoloaded.has('totp') && !showTotpSecretField ? (
                /* ── Path A: stored-secret, ask for 6-digit only ─── */
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
                    autoFocus={autoloaded.has('master')}
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
              ) : (
                /* ── Path B: bootstrap, ask for TOTP secret only ─── */
                <label className="settings-group__field">
                  <span>TOTP secret</span>
                  <input
                    type="password"
                    placeholder="hex (40 chars) or base32 (32 chars)"
                    value={totpSecret}
                    onChange={(e) => { setTotpSecret(e.target.value); clearFieldError('totpSecret'); }}
                    autoFocus
                    disabled={busy}
                    className={errors.totpSecret ? 'input--error' : ''}
                  />
                  {errors.totpSecret && (
                    <span className="field-error">{errors.totpSecret}</span>
                  )}
                  <span className="unlock-dialog__hint">
                    First-time unlock. Paste the secret from your backup or
                    authenticator. Studio stores it locally so future unlocks
                    only need the 6-digit code.
                  </span>
                </label>
              )}

              {/* Allow operator to swap stored secret if they need to
                  rotate or recover from a phone change. */}
              {autoloaded.has('totp') && !showTotpSecretField && (
                <button
                  type="button"
                  className="unlock-dialog__advanced-toggle"
                  onClick={() => setShowTotpSecretField(true)}
                >
                  Replace stored TOTP secret
                </button>
              )}

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
                <span>
                  Unseal token
                </span>
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
        </div>

        <div className="modal__footer">
          <button className="btn btn--ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            onClick={() => { void handleUnlock(); }}
            disabled={busy}
          >
            {busy ? 'Unlocking…' : 'Unlock'}
          </button>
        </div>
      </div>
    </div>
  );
}
