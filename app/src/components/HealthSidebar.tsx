import type { HealthCheck } from '../lib/types';

interface Props {
  checks: HealthCheck[];
  onFix?: (id: string) => void;
}

const ICON: Record<HealthCheck['severity'], string> = {
  ok: '✓',
  warn: '!',
  err: '×',
};

/**
 * Right-side panel reflecting `sealed-env doctor` state. The eventual
 * Tauri implementation will subscribe to file-system watchers and
 * re-run checks automatically; for the design preview we render a
 * static mock list.
 */
export function HealthSidebar({ checks, onFix }: Props) {
  return (
    <aside className="sidebar">
      <h3>· Health ·</h3>
      {checks.map((check) => (
        <div className="check" key={check.id}>
          <div className={`check__icon check__icon--${check.severity}`}>
            {ICON[check.severity]}
          </div>
          <div className="check__body">
            <div className="check__title">{check.title}</div>
            {check.hint && <div className="check__hint">{check.hint}</div>}
            {check.fixLabel && (
              <button className="check__fix" onClick={() => onFix?.(check.id)}>
                [ {check.fixLabel} → ]
              </button>
            )}
          </div>
        </div>
      ))}
    </aside>
  );
}
