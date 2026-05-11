import { useState, useCallback, useEffect } from 'react';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import QRCode from 'qrcode';
import type { SealedMode, AppSettings, SealedFileContent } from '../lib/types';
import { inspectDirectory, readEnvFile, initKeys, sealFile, ensureGitignore } from '../lib/init';
import { saveVaultCredentials } from '../lib/credstore';

type InitStep = 'folder' | 'mode' | 'source' | 'keys' | 'verify' | 'review';

/**
 * Compute the step sequence for the given mode. `verify` only appears
 * for enterprise (the only mode with a TOTP secret to verify against).
 * Computed dynamically so the step counter ("step X of N") and the
 * Next/Back navigation stay correct in all modes.
 */
function stepsFor(mode: SealedMode): InitStep[] {
  return mode === 'enterprise'
    ? ['folder', 'mode', 'source', 'keys', 'verify', 'review']
    : ['folder', 'mode', 'source', 'keys', 'review'];
}

function nextStepIn(steps: InitStep[], s: InitStep): InitStep {
  const i = steps.indexOf(s);
  return steps[Math.min(i + 1, steps.length - 1)] as InitStep;
}
function prevStepIn(steps: InitStep[], s: InitStep): InitStep {
  const i = steps.indexOf(s);
  return steps[Math.max(i - 1, 0)] as InitStep;
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
  // Phase-3 credstore opt-in (Tier A)
  saveToKeychain: boolean;
  passphrase: string;
  confirmPassphrase: string;
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
  saveToKeychain: true,
  passphrase: '',
  confirmPassphrase: '',
});

/**
 * Passphrase strength heuristic. Returns a tuple of `score` (0..4) and a
 * `label`. Score combines length and character-class variety. Not a true
 * entropy estimate — just a UX nudge so the operator picks something
 * stronger than "password123".
 */
function passphraseStrength(pp: string): { score: number; label: string } {
  if (pp.length === 0) return { score: 0, label: '' };
  let score = 0;
  if (pp.length >= 8) score++;
  if (pp.length >= 12) score++;
  if (pp.length >= 16) score++;
  const hasUpper = /[A-Z]/.test(pp);
  const hasLower = /[a-z]/.test(pp);
  const hasDigit = /\d/.test(pp);
  const hasSymbol = /[^A-Za-z0-9]/.test(pp);
  const variety = [hasUpper, hasLower, hasDigit, hasSymbol].filter(Boolean).length;
  if (variety >= 3) score++;
  score = Math.min(score, 4);
  const labels = ['too short', 'weak', 'fair', 'good', 'strong'];
  return { score, label: labels[score] ?? '' };
}

function stripComments(content: string): string {
  return content
    .split('\n')
    .filter((l) => {
      const t = l.trim();
      return t.length > 0 && !t.startsWith('#');
    })
    .join('\n') + '\n';
}

/**
 * Build an RFC 6238 provisioning URI for the operator's authenticator app.
 *
 * Format: `otpauth://totp/<issuer>:<account>?secret=…&issuer=…`
 *   - issuer  = "sealed-env" (the wire format, not the GUI)
 *   - account = the project folder basename (so authenticators show
 *     "sealed-env (myapp)" instead of a generic "sealed-env-studio")
 *
 * Path separators in the label MUST be URL-encoded; `encodeURIComponent`
 * handles spaces, slashes, accents, etc.
 */
/** Cross-platform basename — strips both POSIX (/) and Windows (\) seps. */
function folderBasename(path: string): string {
  if (!path) return '';
  const cleaned = path.replace(/[\\/]+$/, '');
  const idx = Math.max(cleaned.lastIndexOf('/'), cleaned.lastIndexOf('\\'));
  return idx === -1 ? cleaned : cleaned.slice(idx + 1);
}

function totpUri(secretHex: string, label: string): string {
  const bytes = hexToBytes(secretHex);
  const base32 = base32Encode(bytes);
  const safeLabel = encodeURIComponent(label || 'vault');
  return `otpauth://totp/sealed-env:${safeLabel}?secret=${base32}&issuer=sealed-env&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Compute a TOTP code (RFC 6238) for the given secret + timestamp.
 * Used for local verification — operator scans QR, then types the
 * 6 digits their authenticator shows; we recompute and compare. The
 * secret never leaves the renderer process.
 *
 * Uses Web Crypto API (`crypto.subtle`) — no dependency, no network.
 */
async function generateTotp(secretBytes: Uint8Array, timestampSec: number): Promise<string> {
  const counter = Math.floor(timestampSec / 30);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // Counter is 64-bit big-endian; the high 32 bits stay zero for any
  // realistic Unix timestamp (good until year ~10889 AD).
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

      // Optionally persist keys to the OS credential manager (Tier A).
      // Failure here is operator-visible (keychain locked, no D-Bus, etc.)
      // but does NOT abort the seal — the vault on disk is already valid.
      if (data.saveToKeychain && data.passphrase) {
        try {
          await saveVaultCredentials({
            absolutePath: sealResp.absolutePath,
            credentials: {
              master: data.masterKeyHex,
              ...(data.signingKeyHex ? { signing: data.signingKeyHex } : {}),
              ...(data.totpSecretHex ? { totp: data.totpSecretHex } : {}),
              savedAt: new Date().toISOString(),
            },
            passphrase: data.passphrase,
          });
        } catch (e) {
          // Surface as a non-blocking warning. The vault is sealed; the
          // operator can re-try saving from Settings later.
          setError(
            `Vault sealed, but saving to credential manager failed: ${e}. ` +
            `Copy the keys to your password manager and re-save from Settings.`,
          );
        }
      }

      // Parse rawContent locally to populate the viewer immediately.
      // The file on disk DOES contain these variables (sealed by Rust);
      // we mirror them here so the viewer doesn't show an empty vault
      // until the operator re-opens. Format matches `parse_dotenv` in
      // the Rust side: skip blanks + `#` comments, split on first `=`,
      // strip surrounding double-quotes.
      const parsed: { key: string; value: string }[] = [];
      for (const rawLine of data.rawContent.split('\n')) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;
        const eq = line.indexOf('=');
        if (eq <= 0) continue;
        const key = line.slice(0, eq).trim();
        if (!key) continue;
        let value = line.slice(eq + 1).trim();
        // Strip surrounding double-quotes (mirrors dotenv convention)
        if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
          value = value.slice(1, -1);
        }
        parsed.push({ key, value });
      }

      onComplete({
        path: sealResp.absolutePath,
        mode: data.mode,
        kdf: `argon2id (t=${settings.argon2T},m=${settings.argon2M},p=${settings.argon2P})`,
        created: new Date().toISOString(),
        variables: parsed,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  // ─── Navigation ──────────────────────────────────────────────────────────

  // Dynamic step list — for enterprise, inject 'verify' between keys
  // and review so the operator must prove they scanned the QR before
  // sealing.
  const steps = stepsFor(data.mode);

  const canAdvance = (): boolean => {
    switch (step) {
      case 'folder': return data.folderPath.length > 0;
      case 'mode': return true;
      case 'source': return data.rawContent.trim().length > 0;
      case 'keys': {
        // Enterprise: just need keys generated; verify happens next step.
        // Basic/team: need the "I have copied" checkbox.
        const baseOk = data.masterKeyHex.length > 0 &&
          (data.mode === 'enterprise' || data.copiedReminder);
        if (!baseOk) return false;
        // If opting into keychain save, passphrase must be valid + confirmed.
        if (data.saveToKeychain) {
          if (data.passphrase.length < 8) return false;
          if (data.passphrase !== data.confirmPassphrase) return false;
        }
        return true;
      }
      case 'verify': return data.copiedReminder; // verified === true
      case 'review': return true;
    }
  };

  const handleNext = () => setStep((s) => nextStepIn(steps, s));
  const handleBack = () => { setError(''); setStep((s) => prevStepIn(steps, s)); };

  const stepIndex = steps.indexOf(step) + 1;

  return (
    <div className="wizard">
      <div className="titlebar">
        <div className="traffic-lights">
          <span className="red" />
          <span className="yellow" />
          <span className="green" />
        </div>
        <div className="titlebar__title">New vault — step {stepIndex} of {steps.length}</div>
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
            folderName={folderBasename(data.folderPath)}
            masterKeyHex={data.masterKeyHex}
            signingKeyHex={data.signingKeyHex}
            totpSecretHex={data.totpSecretHex}
            copiedReminder={data.copiedReminder}
            saveToKeychain={data.saveToKeychain}
            passphrase={data.passphrase}
            confirmPassphrase={data.confirmPassphrase}
            onGenerate={() => { void handleGenerateKeys(); }}
            onCopiedReminderChange={(v) => update({ copiedReminder: v })}
            onSaveToKeychainChange={(v) => update({ saveToKeychain: v })}
            onPassphraseChange={(v) => update({ passphrase: v })}
            onConfirmPassphraseChange={(v) => update({ confirmPassphrase: v })}
            busy={busy}
          />
        )}

        {step === 'verify' && (
          <StepVerify
            secretHex={data.totpSecretHex}
            verified={data.copiedReminder}
            onVerified={() => update({ copiedReminder: true })}
          />
        )}

        {step === 'review' && (
          <StepReview
            folderPath={data.folderPath}
            mode={data.mode}
            gitignoreWillChange={data.gitignoreWillChange}
            saveToKeychain={data.saveToKeychain}
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
  folderName,
  masterKeyHex,
  signingKeyHex,
  totpSecretHex,
  copiedReminder,
  saveToKeychain,
  passphrase,
  confirmPassphrase,
  onGenerate,
  onCopiedReminderChange,
  onSaveToKeychainChange,
  onPassphraseChange,
  onConfirmPassphraseChange,
  busy,
}: {
  mode: SealedMode;
  folderName: string;
  masterKeyHex: string;
  signingKeyHex: string;
  totpSecretHex: string;
  copiedReminder: boolean;
  saveToKeychain: boolean;
  passphrase: string;
  confirmPassphrase: string;
  onGenerate: () => void;
  onCopiedReminderChange: (v: boolean) => void;
  onSaveToKeychainChange: (v: boolean) => void;
  onPassphraseChange: (v: string) => void;
  onConfirmPassphraseChange: (v: string) => void;
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
              <TotpProvisioning uri={totpUri(totpSecretHex, folderName)} />
              <p className="wizard__step-desc" style={{ marginTop: 0 }}>
                Scan the QR with your authenticator. On the next step you'll
                enter the 6-digit code to verify the secret reached your
                device intact.
              </p>
            </>
          )}

          <KeychainPanel
            saveToKeychain={saveToKeychain}
            passphrase={passphrase}
            confirmPassphrase={confirmPassphrase}
            onSaveToKeychainChange={onSaveToKeychainChange}
            onPassphraseChange={onPassphraseChange}
            onConfirmPassphraseChange={onConfirmPassphraseChange}
            busy={busy}
          />

          {mode !== 'enterprise' && (
            <label className="wizard__copy-reminder">
              <input
                type="checkbox"
                checked={copiedReminder}
                onChange={(e) => onCopiedReminderChange(e.target.checked)}
              />
              <strong>I have copied all keys to a secure location.</strong>
            </label>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Phase-3 credstore opt-in. Two radio options:
 *  - Save to system credential manager (default): passphrase-wrap the keys,
 *    persist in the OS keychain. Future unlocks need only passphrase + 6-digit code.
 *  - I'll back these up myself: nothing persisted by Studio. Operator is fully
 *    responsible for copying keys to a password manager.
 *
 * Validation lives in canAdvance(): if saveToKeychain is true, passphrase must
 * be >= 8 chars and match confirmPassphrase. The Next button stays disabled
 * until both conditions hold.
 */
function KeychainPanel({
  saveToKeychain,
  passphrase,
  confirmPassphrase,
  onSaveToKeychainChange,
  onPassphraseChange,
  onConfirmPassphraseChange,
  busy,
}: {
  saveToKeychain: boolean;
  passphrase: string;
  confirmPassphrase: string;
  onSaveToKeychainChange: (v: boolean) => void;
  onPassphraseChange: (v: string) => void;
  onConfirmPassphraseChange: (v: string) => void;
  busy: boolean;
}) {
  const strength = passphraseStrength(passphrase);
  const mismatch =
    confirmPassphrase.length > 0 && passphrase !== confirmPassphrase;

  return (
    <div className="wizard__keychain">
      <div className="wizard__keychain-options">
        <label className="settings-group__radio">
          <input
            type="radio"
            name="save-to-keychain"
            checked={saveToKeychain}
            onChange={() => onSaveToKeychainChange(true)}
            disabled={busy}
          />
          <span className="settings-group__radio-marker" aria-hidden="true" />
          <span>
            <strong>Save to system credential manager</strong>
            <span className="wizard__keychain-hint">
              Encrypted with a passphrase. Future unlocks only need
              the passphrase {' '}
              <em>(plus the 6-digit code for enterprise vaults)</em>.
            </span>
          </span>
        </label>

        <label className="settings-group__radio">
          <input
            type="radio"
            name="save-to-keychain"
            checked={!saveToKeychain}
            onChange={() => onSaveToKeychainChange(false)}
            disabled={busy}
          />
          <span className="settings-group__radio-marker" aria-hidden="true" />
          <span>
            <strong>I&apos;ll back these up myself</strong>
            <span className="wizard__keychain-hint">
              Studio stores nothing. You paste master + signing + TOTP from
              your password manager on every unlock.
            </span>
          </span>
        </label>
      </div>

      {saveToKeychain && (
        <>
          <label className="settings-group__field">
            <span>Passphrase</span>
            <input
              type="password"
              placeholder="At least 8 characters; longer is better"
              value={passphrase}
              onChange={(e) => onPassphraseChange(e.target.value)}
              disabled={busy}
              autoComplete="new-password"
            />
            {passphrase.length > 0 && (
              <div className={`wizard__strength wizard__strength--s${strength.score}`}>
                <div className="wizard__strength-bar">
                  <span style={{ width: `${(strength.score / 4) * 100}%` }} />
                </div>
                <span className="wizard__strength-label">{strength.label}</span>
              </div>
            )}
          </label>

          <label className="settings-group__field">
            <span>Confirm passphrase</span>
            <input
              type="password"
              placeholder="Type the passphrase again"
              value={confirmPassphrase}
              onChange={(e) => onConfirmPassphraseChange(e.target.value)}
              disabled={busy}
              autoComplete="new-password"
              className={mismatch ? 'input--error' : ''}
            />
            {mismatch && (
              <span className="field-error">Passphrases do not match.</span>
            )}
          </label>

          <p className="wizard__keychain-warning">
            ⚠ Even when saved, copy the keys to a password manager as recovery.
            If you forget the passphrase or the credential store is wiped
            (OS reinstall, new machine), the password manager is your only
            recovery path.
          </p>
        </>
      )}
    </div>
  );
}

/**
 * Step 5 (enterprise only): TOTP verification gate as its own wizard
 * step. Renders the title/intro plus the `<TotpVerification>` widget.
 * The operator can't reach Review until they prove the secret was
 * scanned correctly.
 */
function StepVerify({
  secretHex,
  verified,
  onVerified,
}: {
  secretHex: string;
  verified: boolean;
  onVerified: () => void;
}) {
  return (
    <div className="wizard__step">
      <h2 className="wizard__step-title">5. Verify TOTP</h2>
      <p className="wizard__step-desc">
        Open your authenticator app and enter the current 6-digit code for
        this vault. Verifying here confirms the secret reached your device
        intact and that your clock matches ours within the ±30s tolerance.
      </p>
      <TotpVerification
        secretHex={secretHex}
        verified={verified}
        onVerified={onVerified}
      />
    </div>
  );
}

/**
 * TOTP verification gate (enterprise only). The operator scans the QR
 * with their authenticator, then types the current 6-digit code here.
 * We recompute the TOTP locally (Web Crypto API, no network) and
 * compare. On match, the wizard's `copiedReminder` flag flips to
 * true and Next becomes enabled.
 *
 * This is the right gate for enterprise mode because:
 *   - It proves the secret was actually provisioned to the operator's
 *     authenticator (a plain checkbox can be lied to).
 *   - It exercises the exact code path that production deploys will
 *     use, surfacing any clock skew issues NOW instead of at runtime.
 *
 * We accept ±1 step skew (90s window total) per RFC 6238 §5.2.
 */
function TotpVerification({
  secretHex,
  verified,
  onVerified,
}: {
  secretHex: string;
  verified: boolean;
  onVerified: () => void;
}) {
  const [code, setCode] = useState('');
  const [status, setStatus] = useState<'idle' | 'checking' | 'wrong'>('idle');

  // Re-check whenever the user finishes typing 6 digits (debounce on length).
  useEffect(() => {
    if (verified) return;
    const trimmed = code.replace(/\D/g, '').slice(0, 6);
    if (trimmed.length !== 6) {
      setStatus('idle');
      return;
    }
    let cancelled = false;
    setStatus('checking');
    void (async () => {
      const secretBytes = hexToBytes(secretHex);
      const now = Math.floor(Date.now() / 1000);
      const candidates = await Promise.all([
        generateTotp(secretBytes, now - 30),
        generateTotp(secretBytes, now),
        generateTotp(secretBytes, now + 30),
      ]);
      if (cancelled) return;
      if (candidates.includes(trimmed)) {
        onVerified();
      } else {
        setStatus('wrong');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [code, secretHex, verified, onVerified]);

  if (verified) {
    return (
      <div className="wizard__totp-verify wizard__totp-verify--ok">
        <span className="wizard__totp-verify-mark">✓</span>
        <div>
          <strong>Authenticator verified.</strong>
          <p className="wizard__totp-verify-hint">
            The code you entered matches what we expect. You can proceed.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="wizard__totp-verify">
      <label className="wizard__totp-verify-label" htmlFor="totp-code">
        Enter the 6-digit code from your authenticator
      </label>
      <input
        id="totp-code"
        className={`wizard__totp-verify-input${status === 'wrong' ? ' wizard__totp-verify-input--error' : ''}`}
        type="text"
        inputMode="numeric"
        autoComplete="one-time-code"
        placeholder="123 456"
        value={code}
        onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
        maxLength={6}
      />
      {status === 'wrong' && (
        <span className="field-error">
          Code doesn't match. Wait for the next 30s window and try again, or
          re-scan the QR if your authenticator wasn't set up yet.
        </span>
      )}
      {status === 'checking' && (
        <span className="wizard__totp-verify-hint">Checking…</span>
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

/**
 * TOTP provisioning block — renders the URI as text plus a locally
 * generated QR code so the operator can scan it from their phone
 * (Authy, Google Authenticator, etc.) without sending the secret to
 * any third-party API. QR rendering uses the `qrcode` npm package
 * (pure JS, MIT) — no network call, no telemetry.
 */
function TotpProvisioning({ uri }: { uri: string }) {
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [showUri, setShowUri] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void QRCode.toDataURL(uri, {
      width: 220,
      margin: 1,
      errorCorrectionLevel: 'M',
      color: { dark: '#1a1612', light: '#f1ebe0' },
    }).then((d) => {
      if (!cancelled) setQrDataUrl(d);
    });
    return () => {
      cancelled = true;
    };
  }, [uri]);

  const handleCopy = () => {
    void navigator.clipboard.writeText(uri).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="wizard__totp-block">
      <div className="wizard__totp-qr-wrap">
        {qrDataUrl ? (
          <img
            className="wizard__totp-qr"
            src={qrDataUrl}
            alt="Scan to provision TOTP in your authenticator app"
          />
        ) : (
          <div className="wizard__totp-qr-placeholder">…</div>
        )}
      </div>
      <div className="wizard__totp-meta">
        <span className="wizard__totp-uri-label">Scan with your authenticator</span>
        <p className="wizard__totp-help">
          Scan this QR with Authy, Google Authenticator, 1Password or any
          RFC 6238 app. Or use the URI manually below.
        </p>
        <div className="wizard__totp-actions">
          <button
            type="button"
            className="btn btn--ghost btn--small"
            onClick={() => setShowUri((v) => !v)}
          >
            {showUri ? 'Hide URI' : 'Show URI'}
          </button>
          <button
            type="button"
            className="btn btn--ghost btn--small"
            onClick={handleCopy}
          >
            {copied ? 'Copied!' : 'Copy URI'}
          </button>
        </div>
        {showUri && (
          <code className="wizard__totp-uri-value">{uri}</code>
        )}
      </div>
    </div>
  );
}

function StepReview({
  folderPath,
  mode,
  gitignoreWillChange,
  saveToKeychain,
  variableCount,
  argon2,
}: {
  folderPath: string;
  mode: SealedMode;
  gitignoreWillChange: boolean;
  saveToKeychain: boolean;
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
        <dt>Credentials</dt>
        <dd>
          {saveToKeychain
            ? 'Save to system credential manager (passphrase-protected)'
            : 'Not stored — back these up yourself'}
        </dd>
      </dl>
    </div>
  );
}
