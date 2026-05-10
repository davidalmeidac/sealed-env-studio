import type { RecentEntry } from '../lib/types';
import { ModeBadge } from './ModeBadge';

interface Props {
  entries: RecentEntry[];
  onOpen: (entry: RecentEntry) => void;
  onRemove: (id: string) => void;
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  } catch {
    return iso;
  }
}

function basename(p: string): string {
  return p.replace(/\\/g, '/').split('/').pop() ?? p;
}

function dirname(p: string): string {
  const norm = p.replace(/\\/g, '/');
  const idx = norm.lastIndexOf('/');
  return idx === -1 ? '' : norm.slice(0, idx + 1);
}

export function RecentProjects({ entries, onOpen, onRemove }: Props) {
  // Sorted by lastOpenedAt descending (already done by Rust, but enforce here too)
  const sorted = [...entries].sort((a, b) =>
    b.lastOpenedAt.localeCompare(a.lastOpenedAt),
  );

  if (sorted.length === 0) {
    return (
      <div className="recents">
        <h2 className="recents__heading">Recents</h2>
        <p className="recents__empty">No recent vaults — open or create one above.</p>
      </div>
    );
  }

  return (
    <div className="recents">
      <h2 className="recents__heading">Recents</h2>
      <ul className="recents__list">
        {sorted.map((entry) => (
          <li key={entry.id} className="recents__item">
            <button
              className="recents__item-body"
              onClick={() => onOpen(entry)}
            >
              <div className="recents__item-name">
                <span className="filename">{basename(entry.absolutePath)}</span>
                <ModeBadge mode={entry.mode} />
              </div>
              <div className="recents__item-path">{dirname(entry.absolutePath)}</div>
              <div className="recents__item-date">{formatDate(entry.lastOpenedAt)}</div>
            </button>
            <button
              className="btn btn--ghost btn--small recents__item-remove"
              title="Remove from recents"
              aria-label="Remove from recents"
              onClick={(e) => {
                e.stopPropagation();
                onRemove(entry.id);
              }}
            >
              ×
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
