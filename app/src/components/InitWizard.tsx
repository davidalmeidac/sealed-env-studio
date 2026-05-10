import { useState, useCallback } from 'react';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import type { SealedMode, AppSettings, SealedFileContent } from '../lib/types';
import { inspectDirectory, readEnvFile, initKeys, sealFile, ensureGitignore } from '../lib/init';

type InitStep = 'folder' | 'mode' | 'source' | 'keys' | 'review';
const STEPS: InitStep[] = ['folder', 'mode', 'source', 'keys', 'review'];

function nextStep(s: InitStep): InitStep {
  const i = STEPS.indexOf(s);
  return STEPS[Math.min(i + 1, STEPS.length - 1)];
}
function prevStep(s: InitStep): InitStep {
  const i = STEPS.indexOf(s);
  return STEPS[Math.max(i - 1, 0)];
}

interface WizardData {
  folderPath: string;
  detectedTemplates: Array<{ fileName: string; absolutePath: string }>;
  hasGitignore: boolean;
  gitignoreCoversEnv: boolean;
  mode: SealedMode;
  selectedTemplatePath: string;
  rawContent: string;
  rawContentSnapshot: string; // original before stripping comments
  showComments: boolean;
  masterKeyHex: string;
  signingKeyHex: string;
  totpSecretHex: string;
  copiedReminder: boolean;
  gitignoreWillChange: boolean;
}

const emptyData = (): WizardData => ({
  folderPath: '',
  detectedTemplates: [],
  hasGitignore: false,
  gitignoreCoversEnv: false,
  mode: 'basic',
  selectedTemplatePath: '',
  rawContent: '',
  rawContentSnapshot: '',
  showComments: true,
  masterKeyHex: '',
  signingKeyHex: '',
  totpSecretHex: '',
  copiedReminder: false,
  gitignoreWillChange: false,
});

function stripComments(content: string): string {
  return content
    .split('\n')
    .filter((l) => {
      const t = l.trim();
      return t.length > 0 && !t.startsWith('#');
    })
    .join('\n') + '\n';
}

function totpUri(secretHex: string): string {
  // Base32-encode the hex secret for a TOTP URI
  const bytes = hexToBytes(secretHex);
  const base32 = base32Encode(bytes);
  return `otpauth://totp/sealed-env-studio?secret=${base32}&issuer=sealed-env-studio&algorithm=SHA1&digits=6&period=30`;
}

function hexToBytes(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

// Minimal RFC 4648 Base32 encoder (no padding)
const B32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += B32_CHARS[(value << (5 - bits)) & 31];
  }
  return out;
}

interface Props {
  settings: AppSettings;
  onComplete: (file: SealedFileContent) => void;
  onCancel: () => void;
}

export function InitWizard({ settings, onComplete, onCancel }: Props) {
  const [step, setStep] = useState<InitStep>('folder');
  const [data, setData] = useState<WizardData>(() => ({
    ...emptyData(),
    mode: settings.defaultMode,
  }));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const update = useCallback((patch: Partial<WizardData>) => {
    setData((d) => ({ ...d, ...patch }));
    setError('');
  }, []);

  // ─── Step 1: Folder ───────────────────────────────────────────────────────

  const handlePickFolder = async () => {
    const selected = await openDialog({
      title: 'Select project folder',
      directory: true,
      multiple: false,
    });
    if (typeof selected !== 'string' || selected.length === 0) return;

    setBusy(true);
    try {
      const resp = await inspectDirectory({ folderPath: selected });
      update({
        folderPath: selected,
        detectedTemplates: resp.detectedTemplates,
        hasGitignore: resp.hasGitignore,
        gitignoreCoversEnv: resp.gitignoreCoversEnv,
        gitignoreWillChange: settings.autoAppendGitignore && !resp.gitignoreCoversEnv,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  // ─── Step 3: Source ───────────────────────────────────────────────────────

  const handleSelectTemplate = async (absPath: string) => {
    if (!absPath) {
      update({ selectedTemplatePath: '', rawContent: '', rawContentSnapshot: '' });
      return;
    }
    setBusy(true);
    try {
      const resp = await readEnvFile({ absolutePath: absPath });
      update({
        selectedTemplatePath: absPath,
        rawContent: resp.rawContent,
        rawContentSnapshot: resp.rawContent,
        showComments: true,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const handleToggleComments = (show: boolean) => {
    if (show) {
      // Restore original snapshot
      update({ showComments: true, rawContent: data.rawContentSnapshot });
    } else {
      // Strip comments but keep snapshot for restoration
      update({ showComments: false, rawContent: stripComments(data.rawContentSnapshot) });
    }
  };

  // ─── Step 4: Keys ─────────────────────────────────────────────────────────

  const handleGenerateKeys = async () => {
    setBusy(true);
    try {
      const resp = await initKeys({ mode: data.mode });
      update({
        masterKeyHex: resp.masterKeyHex,
        signingKeyHex: resp.signingKeyHex ?? '',
        totpSecretHex: resp.totpSecretHex ?? '',
        copiedReminder: false,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  // ─── Step 5: Seal ─────────────────────────────────────────────────────────

  const handleSeal = async () => {
    setBusy(true);
    setError('');
    try {
      const outputPath = data.folderPath.replace(/\\/g, '/') + '/.env.sealed';

      const sealResp = await sealFile({
        mode: data.mode,
        outputPath,
        rawDotenv: data.rawContent,
        masterKeyHex: data.masterKeyHex,
        ...(data.signingKeyHex ? { signingKeyHex: data.signingKeyHex } : {}),
        ...(data.totpSecretHex ? { totpSecretHex: data.totpSecretHex } : {}),
        argon2: {
          t: settings.argon2T,
          m: settings.argon2M,
          p: settings.argon2P,
        },
      });

      // Optionally append .env to .gitignore
      if (data.gitignoreWillChange) {
        await ensureGitignore({ folderPath: data.folderPath });
      }

      onComplete({
        path: sealResp.absolutePath,
        mode: data.mode,
        kdf: `argon2id (t=${settings.argon2T},m=${settings.argon2M},p=${settings.argon2P})`,
        created: new Date().toISOString(),
        variables: [],
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  // ─── Navigation ──────────────────────────────────────────────────────────

  const canAdvance = (): boolean => {
    switch (step) {
      case 'folder': return data.folderPath.length > 0;
      case 'mode': return true;
      case 'source': return data.rawContent.trim().length > 0;
      case 'keys': return data.masterKeyHex.length > 0 && data.copiedReminder;
      case 'review': return true;
    }
  };

  const handleNext = () => setStep((s) => nextStep(s));
  const handleBack = () => { setError(''); setStep((s) => prevStep(s)); };

  const stepIndex = STEPS.indexOf(step) + 1;

  return (
    <div className="wizard">
      <div className="titlebar">
        <div className="traffic-lights">
          <span className="red" />
          <span className="yellow" />
          <span className="green" />
        </div>
        <div className="titlebar__title">New vault — step {stepIndex} of {STEPS.length}</div>
        <div style={{ width: 60 }} />
      </div>

      <div className="wizard__body">
        {step === 'folder' && (
          <StepFolder
            folderPath={data.folderPath}
            detectedTemplates={data.detectedTemplates}
            hasGitignore={data.hasGitignore}
            gitignoreCoversEnv={data.gitignoreCoversEnv}
            onPick={() => { void handlePickFolder(); }}
            busy={busy}
          />
        )}

        {step === 'mode' && (
          <StepMode
            mode={data.mode}
            onChange={(m) => update({ mode: m })}
          />
        )}

        {step === 'source' && (
          <StepSource
            templates={data.detectedTemplates}
            selectedPath={data.selectedTemplatePath}
            rawContent={data.rawContent}
            showComments={data.showComments}
            onSelectTemplate={(p) => { void handleSelectTemplate(p); }}
            onToggleComments={handleToggleComments}
            onContentChange={(c) => update({ rawContent: c })}
            busy={busy}
          />
        )}

        {step === 'keys' && (
          <StepKeys
            mode={data.mode}
            masterKeyHex={data.masterKeyHex}
            signingKeyHex={data.signingKeyHex}
            totpSecretHex={data.totpSecretHex}
            copiedReminder={data.copiedReminder}
            onGenerate={() => { void handleGenerateKeys(); }}
            onCopiedReminderChange={(v) => update({ copiedReminder: v })}
            busy={busy}
          />
        )}

        {step === 'review' && (
          <StepReview
            folderPath={data.folderPath}
            mode={data.mode}
            gitignoreWillChange={data.gitignoreWillChange}
            variableCount={
              data.rawContent.split('\n').filter((l) => {
                const t = l.trim();
                return t.length > 0 && !t.startsWith('#') && t.includes('=');
              }).length
            }
            argon2={`t=${settings.argon2T},m=${settings.argon2M},p=${settings.argon2P}`}
          />
        )}

        {error && <div className="field-error field-error--banner">{error}</div>}
      </div>

      <div className="wizard__footer">
        <button
          className="btn btn--ghost"
          onClick={step === 'folder' ? onCancel : handleBack}
          disabled={busy}
        >
          {step === 'folder' ? 'Cancel' : '← Back'}
        </button>

        {step !== 'review' ? (
          <button
            className="btn btn--primary"
            onClick={handleNext}
            disabled={!canAdvance() || busy}
          >
            Next →
          </button>
        ) : (
          <button
            className="btn btn--primary"
            onClick={() => { void handleSeal(); }}
            disabled={busy}
          >
            {busy ? 'Sealing…' : 'Seal vault'}
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Step sub-components ──────────────────────────────────────────────────────

function StepFolder({
  folderPath,
  detectedTemplates,
  hasGitignore,
  gitignoreCoversEnv,
  onPick,
  busy,
}: {
  folderPath: string;
  detectedTemplates: Array<{ fileName: string; absolutePath: string }>;
  hasGitignore: boolean;
  gitignoreCoversEnv: boolean;
  onPick: () => void;
  busy: boolean;
}) {
  return (
    <div className="wizard__step">
      <h2 className="wizard__step-title">1. Choose project folder</h2>
      <p className="wizard__step-desc">
        Select the directory that contains your <code>.env</code> file. The sealed vault
        will be written next to it as <code>.env.sealed</code>.
      </p>
      <button className="btn btn--primary" onClick={onPick} disabled={busy}>
        {folderPath ? 'Change folder' : 'Browse…'}
      </button>
      {folderPath && (
        <div className="wizard__step-info">
          <div className="wizard__step-path">{folderPath}</div>
          {detectedTemplates.length > 0 && (
            <p>
              Detected: {detectedTemplates.map((t) => t.fileName).join(', ')}
            </p>
          )}
          <p>
            .gitignore: {hasGitignore
              ? (gitignoreCoversEnv ? 'covers .env ✓' : 'exists but does not cover .env')
              : 'not found'}
          </p>
        </div>
      )}
    </div>
  );
}

const MODE_DESCRIPTIONS: Record<SealedMode, string> = {
  basic: 'Single master key. Suitable for solo developers.',
  team: 'Master key + signing key with HMAC integrity. For shared repos.',
  enterprise: 'Master + signing key + TOTP-bound unseal token. Highest security.',
};

function StepMode({
  mode,
  onChange,
}: {
  mode: SealedMode;
  onChange: (m: SealedMode) => void;
}) {
  return (
    <div className="wizard__step">
      <h2 className="wizard__step-title">2. Choose vault mode</h2>
      {(['basic', 'team', 'enterprise'] as SealedMode[]).map((m) => (
        <label key={m} className={`wizard__mode-option ${mode === m ? 'wizard__mode-option--selected' : ''}`}>
          <input
            type="radio"
            name="mode"
            value={m}
            checked={mode === m}
            onChange={() => onChange(m)}
          />
          <span className="wizard__mode-name">
            {m.charAt(0).toUpperCase() + m.slice(1)}
          </span>
          <span className="wizard__mode-desc">{MODE_DESCRIPTIONS[m]}</span>
        </label>
      ))}
    </div>
  );
}

function StepSource({
  templates,
  selectedPath,
  rawContent,
  showComments,
  onSelectTemplate,
  onToggleComments,
  onContentChange,
  busy,
}: {
  templates: Array<{ fileName: string; absolutePath: string }>;
  selectedPath: string;
  rawContent: string;
  showComments: boolean;
  onSelectTemplate: (p: string) => void;
  onToggleComments: (show: boolean) => void;
  onContentChange: (c: string) => void;
  busy: boolean;
}) {
  return (
    <div className="wizard__step">
      <h2 className="wizard__step-title">3. Source .env content</h2>
      <p className="wizard__step-desc">
        Select a detected template or paste your .env content directly.
      </p>

      {templates.length > 0 && (
        <div className="wizard__step-templates">
          <label>
            <span>Load from file:</span>
            <select
              value={selectedPath}
              onChange={(e) => onSelectTemplate(e.target.value)}
              disabled={busy}
            >
              <option value="">— paste manually —</option>
              {templates.map((t) => (
                <option key={t.absolutePath} value={t.absolutePath}>
                  {t.fileName}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}

      {rawContent.length > 0 && (
        <label className="wizard__step-toggle">
          <input
            type="checkbox"
            checked={showComments}
            onChange={(e) => onToggleComments(e.target.checked)}
            disabled={busy}
          />
          <span>Show comments</span>
        </label>
      )}

      <textarea
        className="wizard__step-textarea"
        placeholder="Paste your .env content here…"
        value={rawContent}
        onChange={(e) => onContentChange(e.target.value)}
        rows={12}
        disabled={busy}
        spellCheck={false}
      />
    </div>
  );
}

function StepKeys({
  mode,
  masterKeyHex,
  signingKeyHex,
  totpSecretHex,
  copiedReminder,
  onGenerate,
  onCopiedReminderChange,
  busy,
}: {
  mode: SealedMode;
  masterKeyHex: string;
  signingKeyHex: string;
  totpSecretHex: string;
  copiedReminder: boolean;
  onGenerate: () => void;
  onCopiedReminderChange: (v: boolean) => void;
  busy: boolean;
}) {
  const hasKeys = masterKeyHex.length > 0;

  return (
    <div className="wizard__step">
      <h2 className="wizard__step-title">4. Cryptographic keys</h2>
      <p className="wizard__step-desc">
        Keys are generated locally and never leave this machine. Copy them
        to a secure location before proceeding — they cannot be recovered.
      </p>

      <button
        className="btn btn--primary"
        onClick={onGenerate}
        disabled={busy}
      >
        {hasKeys ? 'Regenerate keys' : 'Generate keys'}
      </button>

      {hasKeys && (
        <div className="wizard__keys">
          <KeyField label="Master key (hex)" value={masterKeyHex} />
          {(mode === 'team' || mode === 'enterprise') && signingKeyHex && (
            <KeyField label="Signing key (hex)" value={signingKeyHex} />
          )}
          {mode === 'enterprise' && totpSecretHex && (
            <>
              <KeyField label="TOTP secret (hex)" value={totpSecretHex} />
              <div className="wizard__totp-uri">
                <span className="wizard__totp-uri-label">TOTP provisioning URI:</span>
                <code className="wizard__totp-uri-value">{totpUri(totpSecretHex)}</code>
              </div>
            </>
          )}

          <label className="wizard__copy-reminder">
            <input
              type="checkbox"
              checked={copiedReminder}
              onChange={(e) => onCopiedReminderChange(e.target.checked)}
            />
            <strong>I have copied all keys to a secure location.</strong>
          </label>
        </div>
      )}
    </div>
  );
}

function KeyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="wizard__key-field">
      <div className="wizard__key-label">{label}</div>
      <div className="wizard__key-row">
        <code className="wizard__key-value">{value}</code>
        <button className="btn btn--ghost btn--small" onClick={handleCopy}>
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
    </div>
  );
}

function StepReview({
  folderPath,
  mode,
  gitignoreWillChange,
  variableCount,
  argon2,
}: {
  folderPath: string;
  mode: SealedMode;
  gitignoreWillChange: boolean;
  variableCount: number;
  argon2: string;
}) {
  return (
    <div className="wizard__step">
      <h2 className="wizard__step-title">5. Review &amp; seal</h2>
      <p className="wizard__step-desc">
        Confirm the settings below, then click <strong>Seal vault</strong> to encrypt
        and write the file.
      </p>
      <dl className="wizard__review">
        <dt>Output path</dt>
        <dd>
          <code>{folderPath.replace(/\\/g, '/')}/.env.sealed</code>
        </dd>
        <dt>Mode</dt>
        <dd>{mode.charAt(0).toUpperCase() + mode.slice(1)}</dd>
        <dt>Variables</dt>
        <dd>{variableCount} key-value pairs</dd>
        <dt>KDF</dt>
        <dd>argon2id ({argon2})</dd>
        {gitignoreWillChange && (
          <>
            <dt>.gitignore</dt>
            <dd><code>.env</code> will be appended</dd>
          </>
        )}
      </dl>
    </div>
  );
}
