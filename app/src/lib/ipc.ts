/**
 * IPC adapter — the ONLY file that imports from @tauri-apps/api/core.
 * Provides a typed invoke() wrapper and snake_case → camelCase helpers.
 * Components and other lib files MUST NOT import from @tauri-apps/api directly.
 */
import { invoke as tauriInvoke } from '@tauri-apps/api/core';

/**
 * Typed invoke wrapper. TReq is sent as the Tauri command argument object;
 * TRes is the expected success shape (camelCase — Tauri serialises Rust
 * serde rename_all = "camelCase" structs directly).
 */
export async function invoke<TRes>(
  command: string,
  args?: Record<string, unknown>,
): Promise<TRes> {
  return tauriInvoke<TRes>(command, args);
}
