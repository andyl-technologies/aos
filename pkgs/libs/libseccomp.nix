##! libseccomp — Seccomp (secure computing) userspace library
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  gperf,
}: let
  upstream = mkGithubUpstream {
    unitId = "libseccomp-2";
    family = "libseccomp";
    stream = "2";
    owner = "pkgs/libs/libseccomp.nix";
    version = "2.6.0";
    upstreamId = "v2.6.0";
    repository = "seccomp/libseccomp";
    tagPrefix = "v";
    major = 2;
    riskFloor = "high";
    source = {
      authority = "github.com";
      path = [
        "seccomp"
        "libseccomp"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "libseccomp-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-g7YIUjLRWIw3ncm5yuR7s3QHzyYubnSZPGG6ctKnhNw=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libseccomp";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    # Linux 6.16 added open_tree_attr(2) after libseccomp 2.6.0 cut its
    # syscall table at Linux 6.13. Keep the name resolver synchronized with
    # the AOS 6.18 UAPI instead of relying on an unknown-syscall default.
    patches = [./patches/libseccomp-0001-open-tree-attr.patch];

    buildDeps = [
      gnumake
      gperf
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libseccomp-${version}
        '';
      }
      {
        name = "patch-source";
        script = ''
          # Updating syscalls.csv regenerates the perfect hash through this
          # release script. AOS has no FHS /bin/bash.
          sed -i "1s|^#!/bin/bash$|#!$CONFIG_SHELL|" src/arch-gperf-generate
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --enable-shared
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
      {
        name = "check";
        script = ''
          required_syscalls="clone clone3 mount umount umount2 pivot_root setns unshare bpf init_module finit_module delete_module perf_event_open ptrace fsopen fsconfig fsmount fspick open_tree open_tree_attr move_mount mount_setattr"

          for architecture in x86_64 aarch64; do
            for syscall_name in $required_syscalls; do
              resolved="$($out/bin/scmp_sys_resolver -a "$architecture" "$syscall_name")"
              if [ "$resolved" = "-1" ]; then
                echo "ERROR: libseccomp cannot resolve $syscall_name on $architecture" >&2
                exit 1
              fi
            done

            resolved="$($out/bin/scmp_sys_resolver -a "$architecture" open_tree_attr)"
            if [ "$resolved" != "467" ]; then
              echo "ERROR: open_tree_attr resolved to $resolved on $architecture, expected 467" >&2
              exit 1
            fi
          done
        '';
      }
    ];

    meta = {
      description = "libseccomp — enhanced seccomp (mode 2) userspace library";
      homepage = "https://github.com/seccomp/libseccomp";
      license = "LGPL-2.1-only";
    };
  }
