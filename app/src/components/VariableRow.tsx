import type { SealedVariable } from '../data/mock';

interface Props {
  variable: SealedVariable;
  revealed: boolean;
  onToggleReveal: () => void;
  onEdit: () => void;
}

/**
 * One row in the variable table. Value is masked unless explicitly
 * revealed by the operator.
 *
 * In the Tauri version, the plaintext value will live in Rust-owned
 * memory and only cross to the renderer when actively revealed,
 * never as the default state. For Phase-1 mock we simulate that by
 * keeping the value in JS but applying a CSS mask.
 */
export function VariableRow({ variable, revealed, onToggleReveal, onEdit }: Props) {
  const maskLength = Math.min(44, Math.max(8, variable.value.length));
  const masked = '●'.repeat(maskLength);

  return (
    <tr>
      <td>
        <span className="var-key">{variable.key}</span>
      </td>
      <td>
        <span className={revealed ? 'var-value' : 'var-value var-value--masked'}>
          {revealed ? variable.value : masked}
        </span>
      </td>
      <td>
        <div className="row-actions">
          <button className="btn btn--ghost btn--small" onClick={onToggleReveal}>
            {revealed ? 'Hide' : 'Reveal'}
          </button>
          <button className="btn btn--ghost btn--small" onClick={onEdit}>
            Edit
          </button>
        </div>
      </td>
    </tr>
  );
}
