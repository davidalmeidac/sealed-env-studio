import { useState, useEffect } from 'react';
import type { AppSettings, RecentEntry, SealedMode } from '../lib/types';
import { hasVaultCredentials, clearVaultCredentials } from '../lib/credstore';

// Argon2id minimums per spec OQ-2
const ARGON2_T_MIN = 2;
const ARGON2_M_MIN = 16384;
const ARGON2_P_MIN = 1;

interface Props {
  initial: AppSettings;
  recents: RecentEntry[];
  onSave: (settings: AppSettings) => void;
  onClearRecents: () => void;
  onDismiss: () => void;
}

interface FieldErrors {
  argon2T?: string;
  argon2M?: string;
  argon2P?: string;
}

export function SettingsModal({ initial, recents, onSave, onClearRecents, onDismiss }: Props) {
  const [draft, setDraft] = useState<AppSettings>({ ...initial });
  const [errors, setErrors] = useState<FieldErrors>({});
  const [savedCreds, setSavedCreds] = useState<RecentEntry[]>([]);
  const [credsProbing, setCredsProbing] = useState(true);

  // Probe the OS keychain for each recent to figure out which have saved creds.
  // keyring doesn't enumerate — we test each known path. Recents is the
  // canonical list of vaults Studio has seen, so this covers the realistic set.
  useEffect(() => {
    let cancelled = false;
    setCredsProbing(true);
    void Promise.all(
      recents.map(async (r) => {
        try {
          const has = await hasVaultCredentials({ absolutePath: r.absolutePath });
          return has ? r : null;
        } catch {
          return null;
        }
      }),
    ).then((results) => {
      if (cancelled) return;
      setSavedCreds(results.filter((r): r is RecentEntry => r !== null));
      setCredsProbing(false);
    });
    return () => { cancelled = true; };
  }, [recents]);

  const handleClearOne = async (entry: RecentEntry) => {
    try {
      await clearVaultCredentials({ absolutePath: entry.absolutePath });
      setSavedCreds((prev) => prev.filter((e) => e.id !== entry.id));
    } catch {
      // Non-fatal; the operator can retry. Silent for now.
    }
  };

  const handleClearAll = async () => {
    const targets = [...savedCreds];
    await Promise.all(
      targets.map((e) =>
        clearVaultCredentials({ absolutePath: e.absolutePath }).catch(() => {}),
      ),
    );
    setSavedCreds([]);
  };

  const validate = (): FieldErrors => {
    const e: FieldErrors = {};
    if (draft.argon2T < ARGON2_T_MIN)
      e.argon2T = `Minimum is ${ARGON2_T_MIN}`;
    if (draft.argon2M < ARGON2_M_MIN)
      e.argon2M = `Minimum is ${ARGON2_M_MIN} KB (16 MB)`;
    if (draft.argon2P < ARGON2_P_MIN)
      e.argon2P = `Minimum is ${ARGON2_P_MIN}`;
    return e;
  };

  const handleSave = () => {
    const e = validate();
    if (Object.keys(e).length > 0) {
      setErrors(e);
      return;
    }
    onSave(draft);
  };

  const setMode = (m: SealedMode) =>
    setDraft((d) => ({ ...d, defaultMode: m }));

  const setIntField = (
    field: keyof Pick<AppSettings, 'argon2T' | 'argon2M' | 'argon2P'>,
    raw: string,
  ) => {
    const n = parseInt(raw, 10);
    setDraft((d) => ({ ...d, [field]: isNaN(n) ? d[field] : n }));
    setErrors((e) => {
      const next = { ...e };
      delete next[field];
      return next;
    });
  };

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="Settings">
      <div className="modal">
        <div className="modal__header">
          <h2 className="modal__title">Settings</h2>
          <button
            className="btn btn--ghost btn--icon modal__close"
            onClick={onDismiss}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="modal__body">
          {/* Default mode */}
          <fieldset className="settings-group">
            <legend className="settings-group__label">Default vault mode</legend>
            {(['basic', 'team', 'enterprise'] as SealedMode[]).map((m) => (
              <label key={m} className="settings-group__radio">
                <input
                  type="radio"
                  name="defaultMode"
                  value={m}
                  checked={draft.defaultMode === m}
                  onChange={() => setMode(m)}
                />
                <span className="settings-group__radio-label">
                  {m.charAt(0).toUpperCase() + m.slice(1)}
                </span>
              </label>
            ))}
          </fieldset>

          {/* Behaviour toggles */}
          <div className="settings-group">
            <label className="settings-group__toggle">
              <input
                type="checkbox"
                checked={draft.autoAppendGitignore}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, autoAppendGitignore: e.target.checked }))
                }
              />
              <span>Auto-append <code>.env</code> to <code>.gitignore</code> on seal</span>
            </label>
            <label className="settings-group__toggle">
              <input
                type="checkbox"
                checked={draft.maskValues}
                onChange={(e) =>
                  setDraft((d) => ({ ...d, maskValues: e.target.checked }))
                }
              />
              <span>Mask values in viewer by default</span>
            </label>
          </div>

          {/* Argon2id parameters */}
          <fieldset className="settings-group">
            <legend className="settings-group__label">
              Argon2id KDF parameters
            </legend>
            <div className="settings-group__fields">
              <label className="settings-group__field">
                <span>t (time cost)</span>
                <input
                  type="number"
                  min={ARGON2_T_MIN}
                  value={draft.argon2T}
                  onChange={(e) => setIntField('argon2T', e.target.value)}
                  className={errors.argon2T ? 'input--error' : ''}
                />
                {errors.argon2T && (
                  <span className="field-error">{errors.argon2T}</span>
                )}
              </label>
              <label className="settings-group__field">
                <span>m (memory KB)</span>
                <input
                  type="number"
                  min={ARGON2_M_MIN}
                  value={draft.argon2M}
                  onChange={(e) => setIntField('argon2M', e.target.value)}
                  className={errors.argon2M ? 'input--error' : ''}
                />
                {errors.argon2M && (
                  <span className="field-error">{errors.argon2M}</span>
                )}
              </label>
              <label className="settings-group__field">
                <span>p (parallelism)</span>
                <input
                  type="number"
                  min={ARGON2_P_MIN}
                  value={draft.argon2P}
                  onChange={(e) => setIntField('argon2P', e.target.value)}
                  className={errors.argon2P ? 'input--error' : ''}
                />
                {errors.argon2P && (
                  <span className="field-error">{errors.argon2P}</span>
                )}
              </label>
            </div>
          </fieldset>

          {/* Saved credentials */}
          <fieldset className="settings-group">
            <legend className="settings-group__label">Saved credentials</legend>
            {credsProbing ? (
              <p className="settings-group__hint">Checking the system credential manager…</p>
            ) : savedCreds.length === 0 ? (
              <p className="settings-group__hint">
                No vaults have credentials saved on this machine. Saving happens at the end
                of the Init Wizard, or anytime by unlocking with raw keys and re-running the
                wizard&apos;s save step.
              </p>
            ) : (
              <>
                <ul className="settings-creds__list">
                  {savedCreds.map((entry) => {
                    const filename = entry.absolutePath
                      .replace(/\\/g, '/')
                      .split('/')
                      .pop() ?? entry.absolutePath;
                    const dir = (() => {
                      const norm = entry.absolutePath.replace(/\\/g, '/');
                      const idx = norm.lastIndexOf('/');
                      return idx === -1 ? '' : norm.slice(0, idx + 1);
                    })();
                    return (
                      <li key={entry.id} className="settings-creds__item">
                        <div className="settings-creds__item-info">
                          <div className="settings-creds__item-name">
                            <span className="filename">{filename}</span>
                            <span className={`mode-badge mode-badge--${entry.mode}`}>
                              {entry.mode.charAt(0).toUpperCase() + entry.mode.slice(1)}
                            </span>
                          </div>
                          <div className="settings-creds__item-path">{dir}</div>
                        </div>
                        <button
                          type="button"
                          className="btn btn--ghost btn--small"
                          onClick={() => { void handleClearOne(entry); }}
                          aria-label={`Clear saved credentials for ${filename}`}
                        >
                          Clear
                        </button>
                      </li>
                    );
                  })}
                </ul>
                <button
                  type="button"
                  className="btn btn--ghost btn--small settings-creds__clear-all"
                  onClick={() => { void handleClearAll(); }}
                >
                  Clear all saved credentials
                </button>
              </>
            )}
          </fieldset>

          {/* Danger zone */}
          <div className="settings-group settings-group--danger">
            <p className="settings-group__label">Danger zone</p>
            <button
              className="btn btn--ghost btn--small"
              onClick={onClearRecents}
            >
              Clear recents
            </button>
          </div>
        </div>

        <div className="modal__footer">
          <button className="btn btn--ghost" onClick={onDismiss}>
            Cancel
          </button>
          <button className="btn btn--primary" onClick={handleSave}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
