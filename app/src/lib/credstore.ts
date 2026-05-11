/**
 * Typed wrappers for the credstore Tauri commands (Tier A: OS keychain +
 * passphrase wrap). All keychain I/O surfaces as ValidationError to the
 * caller; bad passphrase / wrong vault_id / tampered blob surface as
 * "Could not load credentials" (oracle-defended DecryptFailed at the Rust
 * boundary).
 */
import { invoke } from './ipc';
import type {
  VaultCredentials,
  SaveCredsRequest,
  LoadCredsRequest,
  HasCredsRequest,
  ClearCredsRequest,
  ChangePassphraseRequest,
} from './types';

export async function saveVaultCredentials(req: SaveCredsRequest): Promise<void> {
  return invoke<void>('save_vault_credentials', { req });
}

export async function loadVaultCredentials(
  req: LoadCredsRequest,
): Promise<VaultCredentials> {
  return invoke<VaultCredentials>('load_vault_credentials', { req });
}

export async function hasVaultCredentials(req: HasCredsRequest): Promise<boolean> {
  return invoke<boolean>('has_vault_credentials', { req });
}

export async function clearVaultCredentials(req: ClearCredsRequest): Promise<void> {
  return invoke<void>('clear_vault_credentials', { req });
}

export async function changePassphrase(req: ChangePassphraseRequest): Promise<void> {
  return invoke<void>('change_passphrase', { req });
}
