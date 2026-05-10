import { useMemo, useState } from 'react';

import { mockFile, mockHealthChecks } from './data/mock';
import { ModeBadge } from './components/ModeBadge';
import { VariableViewer } from './components/VariableViewer';
import { HealthSidebar } from './components/HealthSidebar';

/**
 * App shell — desktop window chrome + topbar + toolbar + main area
 * + footer. Renders the Variable Viewer with mock data for Phase-1
 * design work.
 *
 * Once Phase 1 ships:
 *   - mock data → IPC call into Rust core
 *   - filterText / revealed state stays exactly the same shape
 *   - the chrome stays the same; we just hide .titlebar when
 *     wrapped by Tauri (which provides a native one).
 */
export function App() {
  const [filterText, setFilterText] = useState('');

  const lastSealedRel = useMemo(() => relativeTime(mockFile.lastSealed), []);

  return (
    <div className="app-shell">
      {/* macOS-style titlebar (will be replaced by Tauri's native one) */}
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
          <span>{dirname(mockFile.path)}</span>
          <span className="filename">{basename(mockFile.path)}</span>
        </div>
        <ModeBadge mode={mockFile.mode} />
      </div>

      {/* Toolbar: search, add, diff, more, save & re-seal */}
      <div className="toolbar">
        <div className="search">
          <input
            type="text"
            placeholder="Filter variables..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
          />
        </div>
        <button className="btn btn--ghost">+ Add</button>
        <button
          className="btn btn--ghost btn--icon"
          title="Diff with another file"
          aria-label="Diff with another file"
        >
          ⇆
        </button>
        <button
          className="btn btn--ghost btn--icon"
          title="More"
          aria-label="More"
        >
          ⋯
        </button>
        <button className="btn btn--primary">Save &amp; Re-seal</button>
      </div>

      {/* Main: variables on the left, health sidebar on the right */}
      <div className="main">
        <VariableViewer file={mockFile} filterText={filterText} />
        <HealthSidebar checks={mockHealthChecks} />
      </div>

      {/* Footer status */}
      <div className="footer">
        <span>
          {mockFile.variables.length} variables · last sealed{' '}
          <span className="stat">{lastSealedRel}</span> · KDF: {mockFile.kdf}
        </span>
        <span className="stat">v0.1.0-pre.1</span>
      </div>
    </div>
  );
}

function basename(p: string): string {
  return p.split('/').pop() ?? p;
}
function dirname(p: string): string {
  const idx = p.lastIndexOf('/');
  return idx === -1 ? '' : p.slice(0, idx + 1);
}

/** Tiny relative-time formatter — good enough for "2h 14m ago". */
function relativeTime(iso: string): string {
  const date = new Date(iso);
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return 'in the future';

  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  const remMin = minutes % 60;
  if (hours < 24) return `${hours}h ${remMin}m ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
