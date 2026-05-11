# AUR packaging — sealed-env Studio

Two paths to install Studio on Arch + derivatives (Manjaro, EndeavourOS, Garuda):

## End user

```bash
yay -S sealed-env-studio-bin
# or
paru -S sealed-env-studio-bin
```

Pulls the latest x86_64 `.deb` from the GitHub Release, unpacks it, lands a
working binary at `/usr/bin/sealed-env-studio` with desktop entry + icons.

## Maintainer

The package is automatically updated by
[`.github/workflows/aur-publish.yml`](../../.github/workflows/aur-publish.yml)
on every `studio-v*` tag. The workflow:

1. Reads the tag (`studio-vX.Y.Z`) → derives `pkgver=X.Y.Z`
2. Downloads the matching `.deb` from the GitHub Release and computes
   `sha256sum`
3. Renders [`PKGBUILD`](PKGBUILD) with the new `pkgver` + `pkgrel=1` + new
   sha256
4. Generates `.SRCINFO` via `makepkg --printsrcinfo`
5. Pushes both files to `ssh+git://aur@aur.archlinux.org/sealed-env-studio-bin.git`

### Required secrets

| Secret | Purpose |
|---|---|
| `AUR_SSH_PRIVATE_KEY` | Ed25519 key registered in [AUR account settings](https://aur.archlinux.org/account/) |
| `AUR_SSH_KNOWN_HOSTS` | Output of `ssh-keyscan aur.archlinux.org` (verified once at setup) |

### Manual bump (fallback)

```bash
git clone ssh://aur@aur.archlinux.org/sealed-env-studio-bin.git
cd sealed-env-studio-bin
# Edit PKGBUILD: bump pkgver, run updpkgsums
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git commit -m "upgpkg: sealed-env-studio-bin X.Y.Z-1"
git push
```
