# HyprAV kernel module as an akmod/kmod (Path 2 in this directory's
# README.md) - the client-side-rebuild alternative to baking av.ko into
# the image. Follows the RPM Fusion `kmodtool` convention so that, on a
# Fedora Atomic / Bazzite host with `akmods` layered, the module is
# rebuilt into /usr/lib/modules/<kver>/extra whenever it boots into a
# kernel it has not built for yet.
#
# This is the KERNEL MODULE only. avd/avctl/av-gui (userspace) come from
# packaging/fedora/hyprav.spec unchanged - they are ordinary RPMs with
# nothing Atomic-specific about them.
#
# HONESTY CAVEAT: this spec mirrors the canonical RPM Fusion kmod/akmod
# template, but has NOT been end-to-end build-verified against a live
# akmods/kmodtool aarch64 Atomic host in this project's environment -
# there is no such host here, the same limitation the Arch-ARM CI leg
# documents in .github/workflows/build-packages.yml. The image-bake path
# (packaging/bazzite/Containerfile) is the route to prefer until this has
# had a real akmods run; corrections from anyone who runs it are welcome.
#
# Build an akmod (default): rpmbuild -bb hyprav-kmod.spec
# Build a kmod for one kernel: rpmbuild -bb --define 'buildforkernels current' ...

%global debug_package %{nil}

# akmod by default = a package whose scriptlets rebuild the module on the
# client when the kernel changes (what you want on Atomic). Override with
# --define 'buildforkernels current' (running kernel) or 'newest'.
%{!?buildforkernels: %global buildforkernels akmod}

# gitcommit / pkgversion: same guarded-%%global idiom, and the same
# caller contract, as packaging/fedora/hyprav.spec - keep the two in
# sync. A literal %% is required in this comment (RPM expands %%-macros
# even inside comments; see the long note in hyprav.spec).
%if 0%{!?gitcommit:1}
%global gitcommit c2051d7
%endif
%if 0%{!?pkgversion:1}
%global pkgversion 0.9.0.129.g%{gitcommit}
%endif

Name:           hyprav-av-kmod
Version:        %{pkgversion}
Release:        1%{?dist}
Summary:        HyprAV kprobe-based execve/file-event kernel module (akmod)

License:        GPL-2.0-only OR MIT
URL:            https://github.com/keanehatescoding/antivirus
Source0:        %{url}/archive/%{gitcommit}/antivirus-%{gitcommit}.tar.gz

# arm64 only: the module hooks __arm64_sys_execve by symbol name (see
# SECURITY.md / packaging/fedora/hyprav.spec's hyprav-dkms ExclusiveArch).
ExclusiveArch:  aarch64

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  kmodtool

# Pull the matching kernel-devel(s). For an akmod build this resolves to
# the akmod build machinery; for a plain kmod build (buildforkernels
# current/newest) it pulls kernel-devel for that kernel.
%{!?kernels:BuildRequires: buildsys-build-rpmfusion-kerneldevpkgs-%{?buildforkernels:%{buildforkernels}}%{!?buildforkernels:current}-%{_target_cpu} }

# kmodtool emits the per-kernel kmod subpackages (and, for
# buildforkernels=akmod, the akmod-%{kmodname} package) and defines
# %{kernel_versions}, %{kmodinstdir_prefix}, %{kmodinstdir_postfix}.
%{expand:%(kmodtool --target %{_target_cpu} --kmodname %{name} %{?buildforkernels:--%{buildforkernels}} %{?kernels:--for-kernels "%{?kernels}"} 2>/dev/null) }

%description
Out-of-tree kernel module (av.ko) that hooks execve and file events via
kprobes and talks to the avd userspace daemon over netlink. Packaged as
an akmod so it is rebuilt on the client against every installed kernel -
the Fedora Atomic / Bazzite counterpart to the DKMS package in
packaging/fedora/hyprav.spec.

arm64 only as shipped - hooks __arm64_sys_execve by symbol name.

%prep
%autosetup -n antivirus-%{gitcommit}
# kmodtool wants a pristine per-kernel source copy; stage one here.
# (The loop in %build copies from this into a build dir per kernel.)

%build
# Build av.ko once per target kernel. kmodtool packs %{kernel_versions}
# as "VER___/path/to/kernel/build" tokens; strip to the KDIR after ___.
# av/Makefile takes KDIR directly.
#
# Per-kernel toolchain selection: if THIS target kernel was Clang/LTO-built,
# build the module with CC=clang LLVM=1 (av/Makefile supports it), detected
# from the target's own .config - the same check packaging/cachyos/PKGBUILD's
# dkms.conf uses. Fedora's stock kernel is GCC-built, so the default path is
# unchanged; a Clang-built target additionally needs clang/llvm present
# (add them to BuildRequires, or ensure they are installed on the akmods
# host, when building for such a kernel).
for kernel_version in %{?kernel_versions}; do
    ver="${kernel_version%%___*}"
    kbuild="${kernel_version##*___}"
    extra=""
    if grep -qs '^CONFIG_CC_IS_CLANG=y' "${kbuild}/.config"; then
        extra="CC=clang LLVM=1"
    fi
    rm -rf _kmodbuild_"${ver}"
    cp -a av _kmodbuild_"${ver}"
    make -C _kmodbuild_"${ver}" KDIR="${kbuild}" ${extra}
done

%install
# Install each built av.ko into the per-kernel path kmodtool expects.
for kernel_version in %{?kernel_versions}; do
    ver="${kernel_version%%___*}"
    install -Dm644 _kmodbuild_"${ver}"/av.ko \
        "%{buildroot}%{kmodinstdir_prefix}/${ver}/%{kmodinstdir_postfix}/av.ko"
done
%{?akmod_install}

%changelog
* Sat Sep 27 2026 keanehatescoding <keanembae@gmail.com> - 0.9.0.129.gc2051d7-1
- Initial akmod packaging of av.ko for Fedora Atomic / Bazzite.
