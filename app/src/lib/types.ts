/**
 * TypeScript types mirroring Rust serde structs at the IPC boundary.
 * All field names are camelCase (snake_case ↔ camelCase conversion happens in lib/ipc.ts).
 * exactOptionalPropertyTypes is ON — optional fields must use the spread pattern,
 * never `field: x ?? undefined`.
 */

// ─── Sealed file modes ────────────────────────────────────────────────────────

export type SealedMode = 'basic' | 'team' | 'enterprise';

// ─── init_keys ────────────────────────────────────────────────────────────────

export interface InitKeysRequest {
  mode: SealedMode;
}

export interface InitKeysResponse {
  masterKeyHex: string;
  signingKeyHex?: string;
  totpSecretHex?: string;
}

// ─── inspect_directory ────────────────────────────────────────────────────────

export interface InspectDirectoryRequest {
  folderPath: string;
}

export interface DetectedTemplate {
  fileName: string;
  absolutePath: string;
}

export interface InspectDirectoryResponse {
  detectedTemplates: DetectedTemplate[];
  existingSealedFiles: string[];
  hasGitignore: boolean;
  gitignoreCoversEnv: boolean;
}

// ─── read_env_file ────────────────────────────────────────────────────────────

export interface ReadEnvFileRequest {
  absolutePath: string;
}

export interface ReadEnvFileResponse {
  rawContent: string;
  detectedFormat: 'dotenv';
}

// ─── seal_file ────────────────────────────────────────────────────────────────

export interface SealFileRequest {
  mode: SealedMode;
  outputPath: string;
  rawDotenv: string;
  masterKeyHex: string;
  signingKeyHex?: string;
  totpSecretHex?: string;
  argon2: { t: number; m: number; p: number };
}

export interface SealFileResponse {
  absolutePath: string;
  bytesWritten: number;
}

// ─── ensure_gitignore ────────────────────────────────────────────────────────

export interface EnsureGitignoreRequest {
  folderPath: string;
}

export interface EnsureGitignoreResponse {
  modified: boolean;
}

// ─── open_sealed_file ────────────────────────────────────────────────────────
// Reads a .env.sealed file from disk and returns its mode + raw content.

export interface OpenSealedFileRequest {
  absolutePath: string;
}

export interface OpenSealedFileResponse {
  mode: SealedMode;
  rawContent: string;
}

// ─── decrypt_vault ────────────────────────────────────────────────────────────
// Decrypts a sealed vault and returns parsed key-value pairs.

export interface DecryptVaultRequest {
  rawContent: string;
  masterKeyHex: string;
  signingKeyHex?: string;
  /** Pre-built `usl_...` token from the CLI. Takes precedence when both fields are present. */
  unsealToken?: string;
  /** Raw TOTP secret hex (40 chars). When provided without an `unsealToken`, Studio mints the token internally. */
  totpSecretHex?: string;
}

export interface ParsedVariable {
  key: string;
  value: string;
}

export interface DecryptVaultResponse {
  variables: ParsedVariable[];
  kdf: string;
  created: string;
}

// ─── mint_unseal_token ────────────────────────────────────────────────────────
// Builds an enterprise unseal token without decrypting. Same wire format as `sealed-env unseal`.

export interface MintUnsealTokenRequest {
  rawContent: string;
  masterKeyHex: string;
  totpSecretHex: string;
  deployId?: string;
  /** Capped to [5, 600]. Default 60. */
  ttlSeconds?: number;
}

export interface MintUnsealTokenResponse {
  unsealToken: string;
  ttlSeconds: number;
  expUnix: number;
}

// ─── read_local_env ───────────────────────────────────────────────────────────
// Opportunistically reads `<folder>/.env.local` and returns SEALED_ENV_* credentials.

export interface ReadLocalEnvRequest {
  folderPath: string;
}

export interface ReadLocalEnvResponse {
  found: boolean;
  masterKeyHex?: string;
  signingKeyHex?: string;
  totpSecretHex?: string;
  unsealToken?: string;
}

// ─── workspace: recents ──────────────────────────────────────────────────────

export interface RecentEntry {
  id: string;
  absolutePath: string;
  mode: SealedMode;
  lastOpenedAt: string;
}

export interface GetRecentsResponse {
  entries: RecentEntry[];
}

export interface PushRecentRequest {
  entry: RecentEntry;
}

export interface RemoveRecentRequest {
  id: string;
}

// ─── workspace: settings ─────────────────────────────────────────────────────

export interface AppSettings {
  defaultMode: SealedMode;
  autoAppendGitignore: boolean;
  maskValues: boolean;
  argon2T: number;
  argon2M: number;
  argon2P: number;
}

export interface SaveSettingsRequest {
  settings: AppSettings;
}

// ─── SealedFileContent (used by App state 'open') ────────────────────────────
// Aggregate type used only by the frontend state machine.

export interface SealedFileContent {
  path: string;
  mode: SealedMode;
  kdf: string;
  created: string;
  variables: ParsedVariable[];
}

// ─── HealthCheck (Phase-1 viewer compat) ─────────────────────────────────────

export type CheckSeverity = 'ok' | 'warn' | 'err';

export interface HealthCheck {
  id: string;
  severity: CheckSeverity;
  title: string;
  hint?: string;
  fixLabel?: string;
}
