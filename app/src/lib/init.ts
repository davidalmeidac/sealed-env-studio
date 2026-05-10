/**
 * Typed wrappers for the 5 core Tauri init commands.
 * snake_case → camelCase conversion is handled automatically by Tauri's
 * serde rename_all = "camelCase" on the Rust side. We only need to pass
 * our camelCase request objects; Tauri serialises them to snake_case when
 * crossing into Rust and deserialises responses back to camelCase.
 */
import { invoke } from './ipc';
import type {
  InitKeysRequest,
  InitKeysResponse,
  InspectDirectoryRequest,
  InspectDirectoryResponse,
  ReadEnvFileRequest,
  ReadEnvFileResponse,
  SealFileRequest,
  SealFileResponse,
  EnsureGitignoreRequest,
  EnsureGitignoreResponse,
} from './types';

export async function initKeys(req: InitKeysRequest): Promise<InitKeysResponse> {
  return invoke<InitKeysResponse>('init_keys', { req });
}

export async function inspectDirectory(
  req: InspectDirectoryRequest,
): Promise<InspectDirectoryResponse> {
  return invoke<InspectDirectoryResponse>('inspect_directory', { req });
}

export async function readEnvFile(
  req: ReadEnvFileRequest,
): Promise<ReadEnvFileResponse> {
  return invoke<ReadEnvFileResponse>('read_env_file', { req });
}

export async function sealFile(req: SealFileRequest): Promise<SealFileResponse> {
  return invoke<SealFileResponse>('seal_file', { req });
}

export async function ensureGitignore(
  req: EnsureGitignoreRequest,
): Promise<EnsureGitignoreResponse> {
  return invoke<EnsureGitignoreResponse>('ensure_gitignore', { req });
}
