import { useMemo, useState } from 'react';

import type { SealedFile } from '../data/mock';
import { VariableRow } from './VariableRow';

interface Props {
  file: SealedFile;
  filterText: string;
}

/**
 * The Variable Viewer — Studio's daily-use screen.
 *
 * Owns state for which keys are currently revealed. The filter text
 * is owned by App so the toolbar's input stays the source of truth
 * (props down, events up).
 *
 * The Tauri version will replace `file.variables` with a live
 * decryption call. The component shape stays the same.
 */
export function VariableViewer({ file, filterText }: Props) {
  const [revealed, setRevealed] = useState<Set<string>>(
    () => new Set(file.variables.filter((v) => v.revealed).map((v) => v.key)),
  );

  const filtered = useMemo(() => {
    const q = filterText.trim().toLowerCase();
    if (!q) return file.variables;
    return file.variables.filter((v) => v.key.toLowerCase().includes(q));
  }, [file.variables, filterText]);

  const toggleReveal = (key: string) => {
    setRevealed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th style={{ width: '38%' }}>Key</th>
            <th>Value</th>
            <th style={{ width: '160px' }} />
          </tr>
        </thead>
        <tbody>
          {filtered.length === 0 ? (
            <tr>
              <td colSpan={3} className="empty-state">
                No variables match &ldquo;{filterText}&rdquo;.
              </td>
            </tr>
          ) : (
            filtered.map((v) => (
              <VariableRow
                key={v.key}
                variable={v}
                revealed={revealed.has(v.key)}
                onToggleReveal={() => toggleReveal(v.key)}
                onEdit={() => {
                  /* Phase 2 — inline editor */
                  // eslint-disable-next-line no-console
                  console.log('edit:', v.key);
                }}
              />
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
