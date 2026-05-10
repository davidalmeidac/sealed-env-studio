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
    <div className="welcome-screen">
      <div className="titlebar">
        <div className="traffic-lights">
          <span className="red" />
          <span className="yellow" />
          <span className="green" />
        </div>
        <div className="titlebar__title">sealed-env Studio</div>
        <button
          className="btn btn--ghost btn--icon titlebar__settings"
          title="Settings"
          aria-label="Settings"
          onClick={onSettings}
        >
          ⚙
        </button>
      </div>

      <div className="welcome-screen__body">
        <div className="welcome-screen__hero">
          <h1 className="welcome-screen__title">sealed-env Studio</h1>
          <p className="welcome-screen__subtitle">
            Create, open, and manage encrypted <code>.env.sealed</code> vaults.
          </p>
          <div className="welcome-screen__actions">
            <button className="btn btn--primary btn--large" onClick={onNewVault}>
              + New vault
            </button>
            <button
              className="btn btn--ghost btn--large"
              onClick={() => { void handleOpenVault(); }}
            >
              Open vault…
            </button>
          </div>
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
