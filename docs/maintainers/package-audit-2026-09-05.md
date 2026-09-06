# Package maintenance audit - 2026-09-05

This point-in-time audit records non-authoritative package-index signals from the complete `aos maintain scan --repology-fallback --repology-limit 400` sweep. Repology findings prioritize maintainer review; a declared direct provider, source hash, signature policy, and package gates still authorize each update.

The scan used inventory envelope `sha256:83ddb6bdba6b6837f31974b35dfe1cb4696d10c180fe522e7ad6a5632ccaca42` and discovery snapshot `sha256:bf8189f47bd0f4a6b1787ec11556855f8cc7b6c8de17d7e5d06e16c6f9765851`.

## Coverage

| Metric | Count |
| --- | ---: |
| Update units | 371 |
| Provider observations | 356 |
| Same-name Repology fallback observations | 327 |
| Newer-version signals | 152 |
| Current-version vulnerability signals | 37 |
| Corroborated license-set changes | 0 |

A vulnerability signal means at least one Repology repository marks the exact current version vulnerable. It is a triage trigger rather than a confirmed repository-wide CVE assessment. Same-name mappings can collide, and version spelling can differ across package managers.

## Remediation started

The aligned zlib signals were verified against the declared `madler/zlib` release provider. The repository package was updated from `1.3.1` to `1.3.2`, including the exact upstream identity and fetched-source hash. Its package build passed for `aarch64-darwin`, `aarch64-linux`, `x86_64-darwin`, and `x86_64-linux` in the maintainer candidate worktree.

A post-update scan used inventory envelope `sha256:108764c882e7129a3137d23970b48cc7396d718982ad630d95eca936715c8cab` and discovery snapshot `sha256:8aa462b70da398cf5f7d913bb46ffdb79069cb25c87feaa1e05cd807e785d1c6`. It reported 151 newer-version and 36 current-version vulnerability signals; zlib was absent from both sets.

## Vulnerability signals

| Update unit | Current version | Repology project |
| --- | --- | --- |
| `bison` | `3.8.2` | `bison` |
| `containerd` | `2.2.1` | `containerd` |
| `coreutils` | `9.5` | `coreutils` |
| `cups` | `2.4.12` | `cups` |
| `curl` | `8.12.1` | `curl` |
| `elfutils` | `0.192` | `elfutils` |
| `etcd` | `3.5.21` | `etcd` |
| `expat` | `2.7.4` | `expat` |
| `flex` | `2.6.4` | `flex` |
| `freetype` | `2.13.3` | `freetype` |
| `git` | `2.48.1` | `git` |
| `gnutls` | `3.8.5` | `gnutls` |
| `go` | `1.26.0` | `go` |
| `gzip` | `1.13` | `gzip` |
| `krb5` | `1.22.1` | `krb5` |
| `libssh2` | `1.11.1` | `libssh2` |
| `libtpms` | `0.10.0` | `libtpms` |
| `libxml2` | `2.12.9` | `libxml2` |
| `libxslt` | `1.1.42` | `libxslt` |
| `nghttp2-1` | `1.68.0` | `nghttp2` |
| `openssh` | `10.3p1` | `openssh` |
| `openssl` | `3.4.1` | `openssl` |
| `patch` | `2.7.6` | `patch` |
| `perl` | `5.40.1` | `perl` |
| `postgresql` | `18.4` | `postgresql` |
| `protobuf` | `29.5` | `protobuf` |
| `rsync` | `3.4.1` | `rsync` |
| `runc` | `1.4.0` | `runc` |
| `socat` | `1.8.0.3` | `socat` |
| `sqlite` | `3.51.2` | `sqlite` |
| `systemd` | `259.1` | `systemd` |
| `tar` | `1.35` | `tar` |
| `unzip` | `6.0` | `unzip` |
| `util-linux` | `2.42.1` | `util-linux` |
| `xz-5` | `5.8.2` | `xz` |
| `zip` | `3.0` | `zip` |
| `zlib-1` | `1.3.1` | `zlib` |

## Newer-version signals

| Update unit | Current version | Reported newest version(s) | Repology project |
| --- | --- | --- | --- |
| `abseil-cpp-20230802` | `20230802.0` | `20260817.0` | `abseil-cpp` |
| `acl` | `2.3.2` | `2.4.0` | `acl` |
| `acpica` | `R2025_04_04` | `20260408` | `acpica` |
| `alsa-lib` | `1.2.13` | `1.2.16.1` | `alsa-lib` |
| `ant` | `1.10.15` | `1.10.17` | `ant` |
| `attr` | `2.5.2` | `2.6.0` | `attr` |
| `audit` | `4.0.2` | `4.2.1` | `audit` |
| `autoconf` | `2.72` | `2.73` | `autoconf` |
| `bash` | `5.2.37` | `5.3.p15, 5.3_p15, 5.3p15` | `bash` |
| `bazel-7` | `7.7.1` | `9.2.0` | `bazel` |
| `bazel-8` | `8.6.0` | `9.2.0` | `bazel` |
| `bazel-9` | `9.0.1` | `9.2.0` | `bazel` |
| `bazel` | `9.0.1` | `9.2.0` | `bazel` |
| `binutils` | `2.41.0` | `2.47` | `binutils` |
| `boost` | `1.87.0` | `1.92.0` | `boost` |
| `bzip2` | `1.0.8` | `1.0.8-2, 1.0.8.2` | `bzip2` |
| `ca-certificates` | `2026-05-14` | `2026-08-13, 2026.08.13, 20260816` | `ca-certificates` |
| `checkpolicy` | `3.10` | `3.11` | `checkpolicy` |
| `chrony` | `4.8` | `4.9` | `chrony` |
| `cilium` | `1.17.3` | `0.20.0` | `cilium` |
| `cmake` | `3.31.6` | `4.4.3` | `cmake` |
| `cni-plugins` | `1.9.0` | `1.9.1` | `cni-plugins` |
| `conntrack-tools` | `1.4.8` | `1.4.9` | `conntrack-tools` |
| `containerd` | `2.2.1` | `2.3.5` | `containerd` |
| `coreutils` | `9.5` | `9.11` | `coreutils` |
| `cryptsetup` | `2.8.4` | `2.8.7` | `cryptsetup` |
| `cups` | `2.4.12` | `2.4.19` | `cups` |
| `curl` | `8.12.1` | `8.22.0, 8.22.0.1, 8.22.0_1` | `curl` |
| `dbus` | `1.14.10` | `1.16.2` | `dbus` |
| `diffutils` | `3.10` | `3.12` | `diffutils` |
| `docbook-xml` | `4.5` | `5.1` | `docbook-xml` |
| `dtc` | `1.7.2` | `1.8.1` | `dtc` |
| `edk2` | `edk2-stable202602` | `202608` | `edk2` |
| `elfutils` | `0.192` | `0.196` | `elfutils` |
| `erofs-utils` | `1.8.10` | `1.9.4` | `erofs-utils` |
| `etcd` | `3.5.21` | `3.7.1` | `etcd` |
| `ethtool` | `6.15` | `7.1` | `ethtool` |
| `expat` | `2.7.4` | `2.8.4` | `expat` |
| `fakeroot` | `1.37.2` | `2.1.4` | `fakeroot` |
| `file` | `5.46` | `5.48` | `file` |
| `findutils` | `4.10.0` | `4.11.0` | `findutils` |
| `firecracker` | `1.14.1` | `1.17.0` | `firecracker` |
| `fmt-12` | `12.1.0` | `12.2.0` | `fmt` |
| `fontconfig` | `2.15.0` | `2.18.3` | `fontconfig` |
| `freetype` | `2.13.3` | `2.14.3` | `freetype` |
| `gawk` | `5.3.1` | `5.4.1` | `gawk` |
| `getent` | `2.39.0` | `2.18.90` | `getent` |
| `git` | `2.48.1` | `2.55.0` | `git` |
| `glib` | `2.82.4` | `2.88.3` | `glib` |
| `glibc` | `2.39.0` | `2.44` | `glibc` |
| `gnupg` | `2.5.20` | `2.5.22` | `gnupg` |
| `gnutls` | `3.8.5` | `3.8.13` | `gnutls` |
| `go` | `1.26.0` | `1.27.1` | `go` |
| `grep` | `3.11` | `3.12` | `grep` |
| `gzip` | `1.13` | `1.14` | `gzip` |
| `hubble` | `1.17.3` | `1.19.4` | `hubble` |
| `icu` | `77.1` | `78.3` | `icu` |
| `inih-58` | `58` | `62` | `inih` |
| `iproute2` | `6.18.0` | `7.2.0` | `iproute2` |
| `iptables` | `1.8.11` | `1.8.13` | `iptables` |
| `jansson-2` | `2.15.0` | `2.15.1` | `jansson` |
| `jemalloc-5` | `5.3.0` | `5.3.1` | `jemalloc` |
| `jq-1` | `1.8.1` | `1.8.2` | `jq` |
| `json-c` | `0.18` | `0.19` | `json-c` |
| `json-glib` | `1.10.6` | `1.10.8` | `json-glib` |
| `just-1` | `1.46.0` | `1.58.0` | `just` |
| `k3s` | `1.35.1-k3s1` | `1.36.4+k3s1` | `k3s` |
| `kmod` | `34` | `34.2` | `kmod` |
| `krb5` | `1.22.1` | `1.22.2` | `krb5` |
| `less` | `668` | `704` | `less` |
| `libarchive` | `3.8.5` | `3.8.9` | `libarchive` |
| `libburn` | `1.5.6` | `1.5.8` | `libburn` |
| `libcap` | `2.77` | `2.78` | `libcap` |
| `libevent` | `2.1.12` | `2.1.13` | `libevent` |
| `libffi-3` | `3.5.2` | `3.8.0` | `libffi` |
| `libgcrypt` | `1.12.2` | `1.12.3` | `libgcrypt` |
| `libgit2-1` | `1.9.2` | `1.9.7` | `libgit2` |
| `libisoburn` | `1.5.6` | `1.5.8.pl02, 1.5.8_p2` | `libisoburn` |
| `libisofs` | `1.5.6` | `1.5.8.pl02, 1.5.8_p2` | `libisofs` |
| `libksba` | `1.8.0` | `1.8.1` | `libksba` |
| `libnftnl` | `1.2.9` | `1.3.2` | `libnftnl` |
| `libseccomp-2` | `2.6.0` | `2.6.1` | `libseccomp` |
| `libselinux` | `3.10` | `3.11` | `libselinux` |
| `libsemanage` | `3.10` | `3.11` | `libsemanage` |
| `libsepol` | `3.10` | `3.11` | `libsepol` |
| `libslirp` | `4.9.1` | `4.9.4` | `libslirp` |
| `libsodium` | `1.0.21` | `1.0.22` | `libsodium` |
| `libtasn1` | `4.19.0` | `4.21.0` | `libtasn1` |
| `libtool` | `2.5.4` | `2.6.2` | `libtool` |
| `libtpms` | `0.10.0` | `0.10.2` | `libtpms` |
| `liburing-2` | `2.12` | `2.15` | `liburing` |
| `libusb-1` | `1.0.29` | `1.0.30` | `libusb` |
| `libxml2` | `2.12.9` | `2.15.4` | `libxml2` |
| `libxslt` | `1.1.42` | `1.1.45` | `libxslt` |
| `lowdown` | `1.2.0` | `3.1.1` | `lowdown` |
| `lsof` | `4.99.4` | `4.99.7` | `lsof` |
| `lvm2` | `2.03.28` | `2.03.42` | `lvm2` |
| `m4` | `1.4.20` | `1.4.21` | `m4` |
| `mariadb` | `11.4.12` | `12.3.3` | `mariadb` |
| `meson` | `1.10.1` | `1.12.0` | `meson` |
| `mpfr` | `4.2.2` | `4.2.2, 4.2.2.00` | `mpfr` |
| `mtools` | `4.0.44` | `4.0.49` | `mtools` |
| `nasm` | `2.16.03` | `3.02, 3.2.0` | `nasm` |
| `nerdctl-2` | `2.2.1` | `2.3.5` | `nerdctl` |
| `nettle` | `3.10.1` | `4.0` | `nettle` |
| `nftables` | `1.1.1` | `1.1.7` | `nftables` |
| `nghttp2-1` | `1.68.0` | `1.70.0` | `nghttp2` |
| `nginx` | `1.30.4` | `1.31.5` | `nginx` |
| `nix` | `2.24.12` | `2.35.2` | `nix` |
| `nodejs` | `22.22.3` | `26.8.1` | `nodejs` |
| `openldap` | `2.6.10` | `2.7.0` | `openldap` |
| `openssh` | `10.3p1` | `10.5.p1, 10.5_p1, 10.5p1` | `openssh` |
| `openssl` | `3.4.1` | `4.0.2` | `openssl` |
| `opkssh` | `0.13.0` | `0.16.0` | `opkssh` |
| `patch` | `2.7.6` | `2.8` | `patch` |
| `patchelf` | `0.18.0` | `0.19.1` | `patchelf` |
| `pcre2-10` | `10.47` | `10.48` | `pcre2` |
| `perl` | `5.40.1` | `5.44.0` | `perl` |
| `pixman` | `0.44.2` | `0.46.4` | `pixman` |
| `policycoreutils` | `3.10` | `3.11` | `policycoreutils` |
| `postgresql` | `18.4` | `18.6, 18.6.0` | `postgresql` |
| `protobuf` | `29.5` | `36.1` | `protobuf` |
| `pyrefly` | `0.64.0` | `1.2.0` | `pyrefly` |
| `readline` | `8.3` | `8.3_p3, 8.3p003, 8.3p3` | `readline` |
| `refpolicy` | `2.20240916` | `2.20260804` | `refpolicy` |
| `rsync` | `3.4.1` | `3.5.0` | `rsync` |
| `runc` | `1.4.0` | `1.5.1` | `runc` |
| `rust` | `1.93.1` | `1.98.1` | `rust` |
| `sed` | `4.9` | `4.10` | `sed` |
| `semodule-utils` | `3.10` | `3.11` | `semodule-utils` |
| `setools` | `4.6.0` | `4.7.1` | `setools` |
| `setuptools` | `75.8.2` | `84.0.0` | `setuptools` |
| `smartmontools` | `7.4` | `7.5` | `smartmontools` |
| `socat` | `1.8.0.3` | `1.8.1.3` | `socat` |
| `sqlite` | `3.51.2` | `3.53.4, 3.53.4.0` | `sqlite` |
| `strace` | `6.18` | `7.2` | `strace` |
| `swtpm` | `0.10.0` | `0.10.2` | `swtpm` |
| `systemd` | `259.1` | `261.2` | `systemd` |
| `tcpdump` | `4.99.5` | `4.99.6` | `tcpdump` |
| `texinfo` | `7.2` | `7.3` | `texinfo` |
| `tpm2-tools` | `5.7` | `5.8` | `tpm2-tools` |
| `tpm2-tss` | `4.1.3` | `4.2.0` | `tpm2-tss` |
| `tzdata` | `2026b` | `2026c` | `tzdata` |
| `unzip` | `6.0` | `6.0, 6.00` | `unzip` |
| `util-linux` | `2.42.1` | `2.42.3` | `util-linux` |
| `which` | `2.21` | `2.25` | `which` |
| `worker-build` | `0.4.2` | `0.8.5` | `worker-build` |
| `xfsprogs` | `6.12.0` | `7.1.1` | `xfsprogs` |
| `xz-5` | `5.8.2` | `5.8.3` | `xz` |
| `zfs` | `2.4.0` | `2.4.4` | `zfs` |
| `zip` | `3.0` | `3.0, 3.00` | `zip` |
| `zlib-1` | `1.3.1` | `1.3.2` | `zlib` |

## License signals

No current/newest comparison had a unanimous, nonempty license set on both sides that differed. Missing or conflicting package-manager license metadata is intentionally not reported as drift.
