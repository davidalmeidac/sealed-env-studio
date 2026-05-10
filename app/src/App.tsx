import { useReducer, useEffect, useState, useMemo } from 'react';
import type { AppSettings, RecentEntry, SealedFileContent, SealedMode } from './lib/types';
import { getSettings, saveSettings, getRecents, pushRecent, removeRecent, clearRecents, openSealedFile } from './lib/workspace';
import { WelcomeScreen } from './components/WelcomeScreen';
import { InitWizard } from './components/InitWizard';
import { SettingsModal } from './components/SettingsModal';
import { UnlockDialog } from './components/UnlockDialog';
import { ModeBadge } from './components/ModeBadge';
import { VariableViewer } from './components/VariableViewer';
import { HealthSidebar } from './components/HealthSidebar';
import type { HealthCheck } from './lib/types';

// ─── State machine ─────────────────────────────────────────────────────────

type NonSettingsState =
  | { kind: 'welcome' }
  | { kind: 'init' }
  | { kind: 'unlocking'; targetPath: string; mode: SealedMode; rawContent: string }
  | { kind: 'open'; file: SealedFileContent };

type AppState =
  | NonSettingsState
  | { kind: 'settings'; previous: NonSettingsState };

type AppEvent =
  | { type: 'NEW_VAULT' }
  | { type: 'OPEN_VAULT'; path: string; mode: SealedMode; rawContent: string }
  | { type: 'OPEN_SETTINGS' }
  | { type: 'DISMISS_SETTINGS' }
  | { type: 'INIT_COMPLETE'; file: SealedFileContent }
  | { type: 'INIT_CANCEL' }
  | { type: 'UNLOCK_SUCCESS'; file: SealedFileContent }
  | { type: 'UNLOCK_CANCEL' }
  | { type: 'CLOSE_VAULT' };

const INITIAL_STATE: AppState = { kind: 'welcome' };

function reducer(state: AppState, event: AppEvent): AppState {
  switch (event.type) {
    case 'NEW_VAULT':
      return { kind: 'init' };

    case 'OPEN_VAULT':
      return {
        kind: 'unlocking',
        targetPath: event.path,
        mode: event.mode,
        rawContent: event.rawContent,
      };

    case 'OPEN_SETTINGS':
      // Prevent nesting settings inside settings
      if (state.kind === 'settings') return state;
      return { kind: 'settings', previous: state };

    case 'DISMISS_SETTINGS':
      if (state.kind === 'settings') return state.previous;
      return state;

    case 'INIT_COMPLETE':
      return { kind: 'open', file: event.file };

    case 'INIT_CANCEL':
      return { kind: 'welcome' };

    case 'UNLOCK_SUCCESS':
      return { kind: 'open', file: event.file };

    case 'UNLOCK_CANCEL':
      return { kind: 'welcome' };

    case 'CLOSE_VAULT':
      return { kind: 'welcome' };
  }
}

// ─── Default health checks (static for Phase-2 scope) ─────────────────────

const DEFAULT_HEALTH: HealthCheck[] = [
  {
    id: 'sealed-valid',
    severity: 'ok',
    title: '.env.sealed valid',
    hint: 'SEALED-ENV-V1 format verified',
  },
  {
    id: 'gitignore',
    severity: 'ok',
    title: 'git ignores .env',
    hint: "Plaintext won't leak to commits",
  },
];

// ─── App ──────────────────────────────────────────────────────────────────

const DEFAULT_SETTINGS: AppSettings = {
  defaultMode: 'basic',
  autoAppendGitignore: true,
  maskValues: false,
  argon2T: 3,
  argon2M: 65536,
  argon2P: 4,
};

export function App() {
  const [state, dispatch] = useReducer(reducer, INITIAL_STATE);
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [recents, setRecents] = useState<RecentEntry[]>([]);
  const [filterText, setFilterText] = useState('');

  // Load settings + recents on mount
  useEffect(() => {
    void getSettings().then(setSettings).catch(() => {});
    void getRecents().then((r) => setRecents(r.entries)).catch(() => {});
  }, []);

  // ─── Event handlers ──────────────────────────────────────────────────────

  const handleOpenVault = async (path: string) => {
    try {
      const resp = await openSealedFile({ absolutePath: path });
      dispatch({
        type: 'OPEN_VAULT',
        path,
        mode: resp.mode,
        rawContent: resp.rawContent,
      });
    } catch {
      // Could not open file — stay on welcome
    }
  };

  const handleOpenRecent = (entry: RecentEntry) => {
    void handleOpenVault(entry.absolutePath);
  };

  const handleRemoveRecent = (id: string) => {
    void removeRecent({ id }).then(() => {
      setRecents((r) => r.filter((e) => e.id !== id));
    });
  };

  const handleSaveSettings = (s: AppSettings) => {
    setSettings(s);
    void saveSettings({ settings: s });
    dispatch({ type: 'DISMISS_SETTINGS' });
  };

  const handleClearRecents = () => {
    void clearRecents().then(() => setRecents([]));
  };

  const handleInitComplete = (file: SealedFileContent) => {
    dispatch({ type: 'INIT_COMPLETE', file });
    // Push to recents
    const entry: RecentEntry = {
      id: crypto.randomUUID(),
      absolutePath: file.path,
      mode: file.mode,
      lastOpenedAt: new Date().toISOString(),
    };
    void pushRecent({ entry }).then(() => setRecents((r) => [entry, ...r].slice(0, 10)));
  };

  const handleUnlockSuccess = (
    result: import('./lib/types').DecryptVaultResponse,
    path: string,
    mode: SealedMode,
    kdf: string,
    created: string,
  ) => {
    const file: SealedFileContent = {
      path,
      mode,
      kdf,
      created,
      variables: result.variables,
    };
    dispatch({ type: 'UNLOCK_SUCCESS', file });
    // Push to recents
    const entry: RecentEntry = {
      id: crypto.randomUUID(),
      absolutePath: path,
      mode,
      lastOpenedAt: new Date().toISOString(),
    };
    void pushRecent({ entry }).then(() => setRecents((r) => [entry, ...r].slice(0, 10)));
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  const lastSealedRel = useMemo(() => {
    if (state.kind !== 'open') return '';
    return relativeTime(state.file.created);
  }, [state]);

  return (
    <>
      {/* Settings modal overlays any state */}
      {state.kind === 'settings' && (
        <SettingsModal
          initial={settings}
          onSave={handleSaveSettings}
          onClearRecents={handleClearRecents}
          onDismiss={() => dispatch({ type: 'DISMISS_SETTINGS' })}
        />
      )}

      {state.kind === 'welcome' && (
        <WelcomeScreen
          recents={recents}
          settings={settings}
          onNewVault={() => dispatch({ type: 'NEW_VAULT' })}
          onOpenVault={(p) => { void handleOpenVault(p); }}
          onOpenRecent={handleOpenRecent}
          onRemoveRecent={handleRemoveRecent}
          onSettings={() => dispatch({ type: 'OPEN_SETTINGS' })}
        />
      )}

      {state.kind === 'init' && (
        <InitWizard
          settings={settings}
          onComplete={handleInitComplete}
          onCancel={() => dispatch({ type: 'INIT_CANCEL' })}
        />
      )}

      {state.kind === 'unlocking' && (
        <UnlockDialog
          path={state.targetPath}
          mode={state.mode}
          rawContent={state.rawContent}
          onUnlocked={(result) =>
            handleUnlockSuccess(
              result,
              state.targetPath,
              state.mode,
              result.kdf,
              result.created,
            )
          }
          onCancel={() => dispatch({ type: 'UNLOCK_CANCEL' })}
        />
      )}

      {state.kind === 'open' && (
        <div className="app-shell">
          {/* macOS-style titlebar */}
          <div className="titlebar">
            <div className="traffic-lights">
              <span className="red" />
              <span className="yellow" />
              <span className="green" />
            </div>
            <div className="titlebar__title">sealed-env Studio</div>
            <div style={{ width: 60 }} />
          </div>

          {/* File path + mode pill */}
          <div className="topbar">
            <div className="topbar__path">
              <span className="icon">📁</span>
              <span>{dirname(state.file.path)}</span>
              <span className="filename">{basename(state.file.path)}</span>
            </div>
            <ModeBadge mode={state.file.mode} />
          </div>

          {/* Toolbar */}
          <div className="toolbar">
            <div className="search">
              <input
                type="text"
                placeholder="Filter variables..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
              />
            </div>
            <button
              className="btn btn--ghost"
              onClick={() => dispatch({ type: 'CLOSE_VAULT' })}
            >
              Close vault
            </button>
            <button
              className="btn btn--ghost btn--icon"
              title="Settings"
              onClick={() => dispatch({ type: 'OPEN_SETTINGS' })}
            >
              ⚙
            </button>
          </div>

          {/* Main area */}
          <div className="main">
            <VariableViewer file={state.file} filterText={filterText} />
            <HealthSidebar checks={DEFAULT_HEALTH} />
          </div>

          {/* Footer */}
          <div className="footer">
            <span>
              {state.file.variables.length} variables · sealed{' '}
              <span className="stat">{lastSealedRel}</span> · KDF: {state.file.kdf}
            </span>
            <span className="stat">v0.2.0-pre.1</span>
          </div>
        </div>
      )}
    </>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function basename(p: string): string {
  return p.replace(/\\/g, '/').split('/').pop() ?? p;
}

function dirname(p: string): string {
  const norm = p.replace(/\\/g, '/');
  const idx = norm.lastIndexOf('/');
  return idx === -1 ? '' : norm.slice(0, idx + 1);
}

function relativeTime(iso: string): string {
  const date = new Date(iso);
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return 'just now';
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  const remMin = minutes % 60;
  if (hours < 24) return `${hours}h ${remMin}m ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
