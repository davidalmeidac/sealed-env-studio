import type { SealedMode } from '../data/mock';

interface Props {
  mode: SealedMode;
}

const LABELS: Record<SealedMode, string> = {
  basic: 'Basic',
  team: 'Team ✓',
  enterprise: 'Enterprise · TOTP',
};

/**
 * Mode pill shown in the top-right of the topbar. Colour-coded:
 *   - basic → ink (default, low-stakes solo dev)
 *   - team → wax (shared repo, HMAC integrity)
 *   - enterprise → ink with wax ring (TOTP-bound deploys)
 */
export function ModeBadge({ mode }: Props) {
  return (
    <span className={`mode-badge mode-badge--${mode}`}>
      {LABELS[mode]}
    </span>
  );
}
