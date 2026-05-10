/**
 * Mock data for the design preview phase. When the Tauri backend
 * lands in Phase 2+, these types stay; the source of the data
 * switches from this file to a Rust IPC call.
 */

export type SealedMode = 'basic' | 'team' | 'enterprise';

export interface SealedFile {
  /** Absolute path on the operator's machine. */
  path: string;
  /** Mode declared in the wire-format header. */
  mode: SealedMode;
  /** When the file was last sealed (ISO 8601). */
  lastSealed: string;
  /** KDF parameters as displayed in the file header. */
  kdf: string;
  /** Wire-format version string. */
  formatVersion: string;
  /** Decrypted variables. Populated only after the master key unlocks. */
  variables: SealedVariable[];
}

export interface SealedVariable {
  key: string;
  /**
   * The decrypted plaintext value. In a real implementation this
   * lives only in Tauri-secured memory, never in DOM/JS state.
   * For the design preview we keep it inline.
   */
  value: string;
  /**
   * Whether the user has currently chosen to reveal this value.
   * Lifecycle is managed by the component, not stored here in real
   * impl — but for the preview we mock it.
   */
  revealed?: boolean;
}

export type CheckSeverity = 'ok' | 'warn' | 'err';

export interface HealthCheck {
  id: string;
  severity: CheckSeverity;
  title: string;
  hint?: string;
  /** Label for the action button if the user can fix it inline. */
  fixLabel?: string;
}

/* ──────────────────────────────────────────────────────────────
 *                          Mock dataset
 * ────────────────────────────────────────────────────────────── */

export const mockFile: SealedFile = {
  path: '~/work/my-app/.env.sealed',
  mode: 'team',
  lastSealed: '2026-05-08T11:14:00Z',
  kdf: 'argon2id (m=64MB, t=3, p=2)',
  formatVersion: 'SEALED-ENV-V1',
  variables: [
    {
      key: 'DATABASE_URL',
      value: 'postgresql://user:****@db-prod.internal:5432/myapp',
      revealed: true,
    },
    {
      key: 'STRIPE_KEY',
      value: '[demo] would-be-stripe-secret-key-xxxxxxxxxxxxxxx',
    },
    {
      key: 'STRIPE_WEBHOOK_SECRET',
      value: '[demo] would-be-stripe-webhook-secret-xxxxxxxxxx',
    },
    {
      key: 'JWT_SECRET',
      value: '[demo] would-be-jwt-signing-key-rotate-quarterly',
    },
    {
      key: 'OPENAI_API_KEY',
      value: '[demo] would-be-openai-key-xxxxxxxxxxxxxxxxxxxx',
    },
    {
      key: 'SENDGRID_API_KEY',
      value: '[demo] would-be-sendgrid-key-xxxxxxxxxxxxxxxxxx',
    },
    {
      key: 'REDIS_URL',
      value: 'redis://default:****@redis-prod.internal:6379/0',
      revealed: true,
    },
    {
      key: 'SENTRY_DSN',
      value: '[demo] would-be-sentry-dsn-https-xxxxx-ingest-io',
    },
    {
      key: 'CDN_TOKEN',
      value: '[demo] would-be-cdn-token-xxxxxxxxxxxxx',
    },
  ],
};

export const mockHealthChecks: HealthCheck[] = [
  {
    id: 'sealed-valid',
    severity: 'ok',
    title: '.env.sealed valid',
    hint: 'SEALED-ENV-V1 · 9 keys · argon2id',
  },
  {
    id: 'master-reachable',
    severity: 'ok',
    title: 'Master key reachable',
    hint: 'Loaded from .env.local',
  },
  {
    id: 'env-local-perms',
    severity: 'warn',
    title: '.env.local mode 0644',
    hint: 'Should be 0600 — readable by other users on this machine.',
    fixLabel: 'Fix permissions',
  },
  {
    id: 'gitignore',
    severity: 'ok',
    title: 'git ignores .env',
    hint: "Plaintext won't leak to commits",
  },
  {
    id: 'cli-version',
    severity: 'warn',
    title: 'sealed-env 0.0.9 in deps',
    hint: '0.1.0 stable available with security fixes',
    fixLabel: 'Upgrade',
  },
  {
    id: 'wire-format',
    severity: 'ok',
    title: 'Wire format up to date',
    hint: 'SEALED-ENV-V1 · frozen',
  },
];
