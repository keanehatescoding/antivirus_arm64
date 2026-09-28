# Packaging

HyprAV splits into the same three pieces in every distro format, because
they have different lifecycles:

| Piece         | What it is                                   | Why separate |
| ------------- | -------------------------------------------- | ------------ |
| `hyprav-dkms` / kmod | the `av.ko` kernel module (source)    | version-pinned to the kernel; rebuilt per kernel |
| `hyprav`      | `avd` daemon + `avctl` CLI                    | plain userspace |
| `hyprav-gui`  | GTK4 management console                       | plain userspace, optional |

The kernel module is **arm64 only** — it hooks `__arm64_sys_execve` by
symbol name and will not build or load on x86_64 (see `SECURITY.md`). The
userspace pieces are arch-independent.

## Which directory for which distro

| Distro family                         | Use                          | Kernel module delivery |
| ------------------------------------- | ---------------------------- | ---------------------- |
| Debian / Ubuntu                       | `debian/`                    | DKMS |
| Arch Linux / Arch Linux ARM           | `packaging/arch/PKGBUILD`    | DKMS |
| **CachyOS** (and other Arch spins)    | `packaging/cachyos/PKGBUILD` | DKMS, Clang/LTO-aware |
| Fedora (traditional, mutable)         | `packaging/fedora/hyprav.spec` | DKMS |
| **Bazzite / Fedora Atomic** (rpm-ostree) | `packaging/bazzite/`      | image-baked, or akmod |

### `arch/` vs `cachyos/`

CachyOS is Arch-based and uses the identical `makepkg` machinery, so the
two PKGBUILDs share all their packaging *logic* — the CachyOS one is a
deliberate near-copy and defers to `arch/PKGBUILD`'s comments for the
shared rationale. Only two things actually differ, both documented at the
top of `cachyos/PKGBUILD`:

1. **Headers.** CachyOS runs `linux-cachyos`, not Arch's stock `linux`,
   so it build-depends on `linux-cachyos-headers` (swap for your spin's
   `-headers` package if you run e.g. `linux-cachyos-lto`).
2. **Clang/LTO kernels.** CachyOS's LTO spins are Clang-built; the DKMS
   `dkms.conf` auto-detects that from the target kernel's `.config` and
   passes `CC=clang LLVM=1` (which `av/Makefile` already supports). A
   GCC-built spin is unaffected.

Note the module is **aarch64-only** (it hooks `__arm64_sys_execve`) while
CachyOS is **x86_64-focused** — there is no official CachyOS aarch64 repo.
So this variant targets an aarch64 host running a CachyOS-flavoured kernel
(CachyOS kernel PKGBUILDs rebuilt for arm64); on a stock x86_64 CachyOS box
the module can't be built at all, and `makepkg` will (correctly) refuse the
`arch=('aarch64')` PKGBUILD there.

### `fedora/` vs `bazzite/`

`fedora/hyprav.spec` targets a **traditional, mutable** Fedora where DKMS
rebuilds on `kernel` upgrades. Bazzite is **Fedora Atomic** (rpm-ostree,
immutable), where DKMS fits poorly — so `packaging/bazzite/` documents
the two paths that suit an image-based OS: baking `av.ko` into a custom
image (recommended; `Containerfile`) or an akmod that rebuilds on the
client (`hyprav-kmod.spec`). Its userspace still comes from
`fedora/hyprav.spec`. See `packaging/bazzite/README.md` for the details.

## CI

`.github/workflows/build-packages.yml` build-tests the `debian/`,
`packaging/arch/`, and `packaging/fedora/` packages on every push/PR. The
`cachyos/` and `bazzite/` variants are **not** wired into CI yet — no
CachyOS or aarch64-Atomic container is available in this project's CI
environment (the same limitation the Arch-ARM leg already notes for its
`menci/archlinuxarm` image). Their validation status, honestly, differs by
path:

- **`cachyos/PKGBUILD`** — its packaging logic is a near-copy of the
  CI-tested `arch/PKGBUILD`, and `namcap PKGBUILD` output is identical to
  it (same lone `W:`, no `E:`). The Clang-detecting `dkms.conf` was checked
  by simulating dkms sourcing it under bash. Not yet built end-to-end on a
  real aarch64 CachyOS host.
- **`bazzite/Containerfile`** — the build steps mirror
  `packaging/fedora/hyprav.spec`'s own `%build`/`%install`, but it has not
  been `podman build`-verified against a live aarch64 Atomic base here.
- **`bazzite/hyprav-kmod.spec`** — follows the RPM Fusion `kmodtool`
  template but has **not** been build-verified against a live
  `akmods`/`kmodtool` host. Treat the Containerfile as the route to prefer
  until this has had a real akmods run.

Each file repeats its own caveat in-comment. Corrections from anyone who
runs these on real hardware are welcome.
