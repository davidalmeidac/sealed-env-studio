# Snap packaging — sealed-env Studio

## End user

```bash
sudo snap install sealed-env --edge
# once promoted to stable:
sudo snap install sealed-env
```

Works on Ubuntu, Pop!_OS, Manjaro (with `snapd`), Fedora (with `snapd`),
and any distro with the Snap runtime. Auto-updates included.

### Permissions

Studio uses `strict` confinement plus these plug interfaces:

- `home` — read/write vault files in the user's home directory
- `removable-media` — vaults on USB or mounted shares
- `network` — required by Tauri's webview runtime (no outbound network from app logic)
- `password-manager-service` — Tier-1 of the credstore (OS Credential Manager via Secret Service)
- `desktop`, `desktop-legacy`, `x11`, `wayland`, `opengl` — standard Tauri desktop integration

Inspect / revoke per-interface:

```bash
snap connections sealed-env
snap disconnect sealed-env:home
snap connect    sealed-env:home
```

## Maintainer

The snap is built + uploaded to the Snap Store by
[`.github/workflows/snap-publish.yml`](../.github/workflows/snap-publish.yml)
on every `studio-v*` tag. The pipeline:

1. `snapcraft pack` inside an Ubuntu 22.04 container
2. Upload via `snapcraft upload --release=<channel>` using a stored macaroon
3. Channel resolution:
   - tag matches `*-alpha*` → `edge`
   - tag matches `*-beta*` / `*-rc*` → `candidate`
   - clean semver (no pre-release suffix) → `stable`

### Required secrets

| Secret | How to create |
|---|---|
| `SNAPCRAFT_STORE_CREDENTIALS` | `snapcraft export-login --snaps sealed-env --channels edge,candidate,stable -` |

### Manual upload (fallback)

```bash
# On an Ubuntu host with snapcraft installed:
snapcraft               # produces sealed-env_<version>_amd64.snap in the working dir
snapcraft upload --release=edge sealed-env_*.snap
```

### First-time Snap Store registration

```bash
snapcraft register sealed-env
# answer the prompts, agree to the Store TOS
```

Only required once per snap name.
