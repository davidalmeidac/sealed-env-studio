/**
 * Typed wrappers for workspace commands: recents, settings, open/decrypt vault.
 */
import { invoke } from './ipc';
import type {
  GetRecentsResponse,
  PushRecentRequest,
  RemoveRecentRequest,
  AppSettings,
  SaveSettingsRequest,
  OpenSealedFileRequest,
  OpenSealedFileResponse,
  DecryptVaultRequest,
  DecryptVaultResponse,
  MintUnsealTokenRequest,
  MintUnsealTokenResponse,
} from './types';

// ─── Recents ─────────────────────────────────────────────────────────────────

export async function getRecents(): Promise<GetRecentsResponse> {
  return invoke<GetRecentsResponse>('get_recents');
}

export async function pushRecent(req: PushRecentRequest): Promise<void> {
  return invoke<void>('push_recent', { req });
}

export async function removeRecent(req: RemoveRecentRequest): Promise<void> {
  return invoke<void>('remove_recent', { req });
}

export async function clearRecents(): Promise<void> {
  return invoke<void>('clear_recents');
}

// ─── Settings ────────────────────────────────────────────────────────────────

export async function getSettings(): Promise<AppSettings> {
  return invoke<AppSettings>('get_settings');
}

export async function saveSettings(req: SaveSettingsRequest): Promise<void> {
  return invoke<void>('save_settings', { req });
}

// ─── Open + Decrypt ──────────────────────────────────────────────────────────

export async function openSealedFile(
  req: OpenSealedFileRequest,
): Promise<OpenSealedFileResponse> {
  return invoke<OpenSealedFileResponse>('open_sealed_file', { req });
}

export async function decryptVault(
  req: DecryptVaultRequest,
): Promise<DecryptVaultResponse> {
  return invoke<DecryptVaultResponse>('decrypt_vault', { req });
}

export async function mintUnsealToken(
  req: MintUnsealTokenRequest,
): Promise<MintUnsealTokenResponse> {
  return invoke<MintUnsealTokenResponse>('mint_unseal_token', { req });
}
