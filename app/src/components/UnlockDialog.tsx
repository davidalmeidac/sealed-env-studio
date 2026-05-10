import { useState } from 'react';
import type { SealedMode, DecryptVaultResponse } from '../lib/types';
import { decryptVault } from '../lib/workspace';

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
  unsealToken?: string;
  generic?: string;
}

export function UnlockDialog({ path, mode, rawContent, onUnlocked, onCancel }: Props) {
  const [masterKey, setMasterKey] = useState('');
  const [signingKey, setSigningKey] = useState('');
  const [unsealToken, setUnsealToken] = useState('');
  const [errors, setErrors] = useState<FieldErrors>({});
  const [busy, setBusy] = useState(false);

  const needsSigning = mode === 'team' || mode === 'enterprise';
  const needsToken = mode === 'enterprise';

  const filename = path.replace(/\\/g, '/').split('/').pop() ?? path;

  const handleUnlock = async () => {
    const e: FieldErrors = {};
    if (!masterKey.trim()) e.masterKey = 'Master key is required';
    if (needsSigning && !signingKey.trim()) e.signingKey = 'Signing key is required';
    if (needsToken && !unsealToken.trim()) e.unsealToken = 'Unseal token is required';

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
        ...(needsToken && unsealToken.trim()
          ? { unsealToken: unsealToken.trim() }
          : {}),
      });
      onUnlocked(result);
    } catch {
      setErrors({ generic: 'Could not decrypt vault. Check your keys and try again.' });
    } finally {
      setBusy(false);
    }
  };

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

          <label className="settings-group__field">
            <span>Master key (hex)</span>
            <input
              type="password"
              placeholder="64 hex characters"
              value={masterKey}
              onChange={(e) => {
                setMasterKey(e.target.value);
                setErrors((prev) => { const n = { ...prev }; delete n.masterKey; return n; });
              }}
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
                onChange={(e) => {
                  setSigningKey(e.target.value);
                  setErrors((prev) => { const n = { ...prev }; delete n.signingKey; return n; });
                }}
                disabled={busy}
                className={errors.signingKey ? 'input--error' : ''}
              />
              {errors.signingKey && (
                <span className="field-error">{errors.signingKey}</span>
              )}
            </label>
          )}

          {needsToken && (
            <label className="settings-group__field">
              <span>Unseal token</span>
              <input
                type="text"
                placeholder="usl_…"
                value={unsealToken}
                onChange={(e) => {
                  setUnsealToken(e.target.value);
                  setErrors((prev) => { const n = { ...prev }; delete n.unsealToken; return n; });
                }}
                disabled={busy}
                className={errors.unsealToken ? 'input--error' : ''}
              />
              {errors.unsealToken && (
                <span className="field-error">{errors.unsealToken}</span>
              )}
            </label>
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
