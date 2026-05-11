import { open as openDialog } from '@tauri-apps/plugin-dialog';
import type { RecentEntry, AppSettings } from '../lib/types';
import { RecentProjects } from './RecentProjects';

interface Props {
  recents: RecentEntry[];
  onNewVault: () => void;
  onOpenVault: (path: string) => void;
  onOpenRecent: (entry: RecentEntry) => void;
  onRemoveRecent: (id: string) => void;
  onSettings: () => void;
  settings: AppSettings;
}

export function WelcomeScreen({
  recents,
  onNewVault,
  onOpenVault,
  onOpenRecent,
  onRemoveRecent,
  onSettings,
}: Props) {
  const handleOpenVault = async () => {
    const selected = await openDialog({
      title: 'Open sealed vault',
      filters: [{ name: 'Sealed vault', extensions: ['sealed'] }],
      multiple: false,
      directory: false,
    });
    if (typeof selected === 'string' && selected.length > 0) {
      onOpenVault(selected);
    }
  };

  return (
    <div className="welcome">
      <button
        className="welcome__settings"
        aria-label="Settings"
        title="Settings"
        onClick={onSettings}
      >
        &#9881;
      </button>

      <div className="welcome__inner">
        <div className="welcome__sigillum" aria-hidden="true">SE</div>

        <h1 className="welcome__title">sealed-env Studio</h1>

        <p className="welcome__tagline">
          Create, open, and manage encrypted <code>.env.sealed</code> vaults.
        </p>

        <div className="welcome__actions">
          <button className="btn btn--primary" onClick={onNewVault}>
            + New vault
          </button>
          <button
            className="btn btn--ghost"
            onClick={() => { void handleOpenVault(); }}
          >
            Open vault…
          </button>
        </div>

        <RecentProjects
          entries={recents}
          onOpen={onOpenRecent}
          onRemove={onRemoveRecent}
        />
      </div>
    </div>
  );
}
