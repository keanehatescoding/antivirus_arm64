# HyprAV on Bazzite / Fedora Atomic (rpm-ostree)

Bazzite is a [Universal Blue](https://universal-blue.org/) image built on
**Fedora Atomic** (rpm-ostree / bootc). The root filesystem is immutable
and composed from an OCI image, which changes how an out-of-tree kernel
module like `av.ko` has to be delivered. The `packaging/fedora/hyprav.spec`
DKMS package is written for a **traditional, mutable** Fedora install and
is *not* the recommended path here — see below.

> **arm64 only.** `av.ko` hooks `__arm64_sys_execve` by symbol name and
> only builds/loads on aarch64 (see `SECURITY.md`). Use an **aarch64**
> Atomic base (Fedora Silverblue/Kinoite aarch64, or an aarch64 Bazzite
> image where one exists). The userspace pieces (`avd`, `avctl`,
> `av-gui`) are arch-independent.

## Why not just `rpm-ostree install hyprav-dkms`?

You *can* layer the Fedora DKMS package, and it may work, but DKMS and
rpm-ostree fit badly together:

- DKMS builds modules into `/var/lib/dkms` and expects to rebuild them on
  the running system after every kernel change. On an Atomic host the
  kernel changes as part of a whole-image deployment swap, not an
  in-place package upgrade, so DKMS's "rebuild on `kernel` update"
  trigger does not fire the way it does on classic Fedora.
- Layered packages are reapplied on top of each new deployment. A DKMS
  build that needs `kernel-devel`, `gcc`, and `make` present at
  *layering time* pulls that whole toolchain into every deployment.
- If a build fails for the newly-deployed kernel, you can be left with
  the module missing exactly when you rebooted into the new kernel.

So this directory documents the two paths that actually suit Atomic,
in recommended order.

## Path 1 (recommended): bake the module into a custom image

Build `av.ko` **once, at image build time**, against the image's own
kernel, and ship it inside the deployment. No client-side compiler, no
DKMS, deterministic and reproducible. This is the Universal Blue-blessed
way to carry a kernel module. See `Containerfile` in this directory for a
complete, commented example you can `podman build` and then rebase onto:

```sh
# Build your image (adjust FROM/base in the Containerfile first)
podman build -t localhost/bazzite-hyprav packaging/bazzite/

# ... push it to a registry your machine can reach, then on the target:
rpm-ostree rebase ostree-unverified-registry:<your-registry>/bazzite-hyprav:latest
systemctl reboot
```

The trade-off: the module is pinned to the kernel baked into that image,
so you rebuild the image when you want a newer kernel. That is the normal
Atomic model — images, not in-place upgrades.

## Path 2: akmod (client-side rebuild via the akmods service)

If you would rather layer a package that rebuilds the module locally when
the kernel changes, `hyprav-kmod.spec` in this directory is an
**akmod/kmod** spec following the RPM Fusion `kmodtool` convention. On
Atomic hosts akmods is the supported mechanism for exactly this (it is
how RPM Fusion's NVIDIA/broadcom/etc. kmods reach uBlue images):

```sh
rpm-ostree install akmods kmodtool
# ... build akmod-hyprav-av from hyprav-kmod.spec (or install it from a
#     COPR that provides it), then layer it:
rpm-ostree install akmod-hyprav-av
```

The `akmods` service rebuilds the module into
`/var/lib/akmods` → `/usr/lib/modules/<kver>/extra` on the next boot into
a kernel it has not built for yet.

> **Status:** the akmod spec here mirrors the canonical RPM Fusion
> kmodtool template but has **not** been end-to-end build-verified
> against a live akmods/Atomic host in this project's environment (same
> honesty caveat the Arch-ARM CI leg carries in
> `.github/workflows/build-packages.yml` — no aarch64 akmods host is
> available here). Treat Path 1 as the tested-in-spirit route and this as
> the convenience route pending a real akmods run. Reports welcome.

## Userspace (`avd`, `avctl`, `av-gui`)

Nothing Atomic-specific: these are ordinary userspace RPMs from
`packaging/fedora/hyprav.spec` (`hyprav`, `hyprav-gui`). Layer them with
`rpm-ostree install`, install them from a COPR, or `dnf install` them
inside a `toolbox`/`distrobox` if you only want the CLI. The
`Containerfile` in Path 1 builds them straight from source into the image
alongside the module.
