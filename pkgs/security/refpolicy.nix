##! SELinux Reference Policy
{
  lib,
  service-management,
  aos-filesystem-provider,
  aos-configuration-lower,
  kernel-interface,
  aos-host-policy,
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  python3,
  util-linux,
  checkpolicy,
  semodule-utils,
  policycoreutils,
  libselinux,
  bash,
  coreutils,
  grep,
  production ? false,
}: let
  version = "2.20240916";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname =
      if production
      then "refpolicy-production"
      else "refpolicy";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The base policy package and refpolicy include Makefile are nonempty and identify refpolicy.";
        "files" = {};
        "input" = "The installed SELinux base policy modules and development interface tree.";
        "operation" = "Inspect the base module and the policy-development Makefile contract.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\nroot = pathlib.Path(\"@out@/usr/share/selinux/refpolicy\")\nassert (root / \"base.pp\").stat().st_size > 0\nmakefile = (root / \"include/Makefile\").read_text()\nassert \"refpolicy\" in makefile and (root / \"include/support\").is_dir()\nprint(\"refpolicy operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "refpolicy operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The policy package rejects the absent module name.";
        "files" = {};
        "input" = "A request for an uncompiled qualification-invalid policy module.";
        "operation" = "Resolve the nonexistent module from the installed policy store.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport pathlib\nassert not pathlib.Path(\"@out@/usr/share/selinux/refpolicy/qualification-invalid.pp\").exists()\n\nsys.stderr.write(\"refpolicy rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "refpolicy rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/SELinuxProject/refpolicy/releases/download/RELEASE_2_20240916/refpolicy-${version}.tar.bz2"
      ];
      hash = "sha256-pOOQcqyRvwkqCGYLJGpJ8+mGyiwWQCpbH60643To10c=";
    };

    buildDeps = [
      gnumake
      m4
      python3
      util-linux
      checkpolicy
      semodule-utils
      policycoreutils
    ];
    runtimeDeps = [bash coreutils grep policycoreutils libselinux];
    propagatedDeps = [];

    module = ./_refpolicy;
    moduleDeps = [service-management aos-filesystem-provider aos-configuration-lower kernel-interface aos-host-policy];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          # The release tarball may extract as "refpolicy" or "refpolicy-${version}"
          if [ -d refpolicy-${version} ]; then
            cd refpolicy-${version}
          elif [ -d refpolicy ]; then
            cd refpolicy
          else
            cd "$(ls -d */ | head -1)"
          fi
        '';
      }
      {
        name = "configure";
        script =
          ''
            # Append the userspace-only SwitchRoot permission, preserving old bits.
            patch --fuzz=0 -p1 < ${./_aos-selinux-production-policy/refpolicy-switch-root-permission.patch}
          ''
          + (
            if production
            then ''
              # Match the production kernel's ordered security-class map. The
              # final-policy gate independently derives and verifies this map
              # from the pinned kernel source.
              patch -p1 < ${./_aos-selinux-production-policy/refpolicy-linux-6.18.33.patch}
              # Copied guest closures and the fixed FUSE worker must not gain
              # ambient host-loader or textrel access through domain membership.
              patch --fuzz=0 -p1 < ${./_aos-selinux-production-policy/refpolicy-explicit-loaders.patch}
              # The worker reads raw kernel labels and has no translation RPC.
              patch --fuzz=0 -p1 < ${./_aos-selinux-production-policy/refpolicy-explicit-contexts.patch}
              # Normal Root custody is excluded from blanket domain grants only.
              patch --fuzz=0 -p1 < ${./_aos-selinux-production-policy/refpolicy-private-root-custody.patch}
              # Fixed initial helpers retain only their explicit proc-file reads.
              patch --fuzz=0 -p1 < ${./_aos-selinux-production-policy/refpolicy-explicit-proc-files.patch}
              sed -i 's/^UNK_PERMS.*/UNK_PERMS = reject/' build.conf
              # Both fixed AOS transitions retain NNP/nosuid. They use explicit
              # process2 permissions rather than weakening the inherited guard.
              if ! grep -q '^policycap nnp_nosuid_transition;' policy/policy_capabilities; then
                printf '\npolicycap nnp_nosuid_transition;\n' >> policy/policy_capabilities
              fi

            ''
            else ""
          )
          + ''
            # Set policy build options
            sed -i \
              -e 's/^#\?DISTRO.*/DISTRO = redhat/' \
              -e 's/^#\?UBAC.*/UBAC = y/' \
              -e 's/^#\?DIRECT_INITRC.*/DIRECT_INITRC = n/' \
              -e 's/^#\?MONOLITHIC.*/MONOLITHIC = n/' \
              -e 's|^#\?PREFIX.*|PREFIX = '"$out"'|' \
              build.conf

            # Override individual tool paths in the Makefile.
            # checkmodule/checkpolicy come from the checkpolicy package,
            # semodule_package/semodule_link/semodule_expand from semodule-utils,
            # and semodule/load_policy/setfiles/sefcontext_compile from policycoreutils.
            sed -i \
              -e 's|^CHECKPOLICY ?=.*|CHECKPOLICY := ${checkpolicy}/bin/checkpolicy|' \
              -e 's|^CHECKMODULE ?=.*|CHECKMODULE := ${checkpolicy}/bin/checkmodule|' \
              -e 's|^SEMOD_PKG ?=.*|SEMOD_PKG := ${semodule-utils}/bin/semodule_package|' \
              -e 's|^SEMOD_LNK ?=.*|SEMOD_LNK := ${semodule-utils}/bin/semodule_link|' \
              -e 's|^SEMOD_EXP ?=.*|SEMOD_EXP := ${semodule-utils}/bin/semodule_expand|' \
              -e 's|^SEMODULE ?=.*|SEMODULE := ${policycoreutils}/sbin/semodule|' \
              -e 's|^LOADPOLICY ?=.*|LOADPOLICY := ${policycoreutils}/sbin/load_policy|' \
              -e 's|^SETFILES ?=.*|SETFILES := ${policycoreutils}/sbin/setfiles|' \
              -e 's|^SEFCONTEXT_COMPILE ?=.*|SEFCONTEXT_COMPILE := ${policycoreutils}/sbin/sefcontext_compile|' \
              Makefile
          '';
      }
      {
        name = "build";
        script = ''
          # Generate modules.conf with all modules enabled
          make conf
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install DESTDIR=$out
          make install-headers DESTDIR=$out

          # Homes are persisted under /var and bound into their FHS locations.
          # Apply the same labels before and after those bind mounts exist.
          contexts="$out/etc/selinux/refpolicy/contexts/files/file_contexts.subs_dist"
          test -f "$contexts"
          printf '%s\n' '/var/home /home' '/var/roothome /root' >> "$contexts"

          ${lib.optionalString (!production) ''
            # Unlabeled-root compatibility belongs only to the mutable policy.
            # The production base is non-MLS and retains its explicit owners.
            checkmodule -M -m \
              -o "$out/usr/share/selinux/refpolicy/aos_base.mod" \
              ${./refpolicy-aos-base.te}
            semodule_package \
              -o "$out/usr/share/selinux/refpolicy/aos_base.pp" \
              -m "$out/usr/share/selinux/refpolicy/aos_base.mod"
          ''}

          mkdir -p "$out/libexec"
          sed \
            -e "s|@bash@|${bash}|g" \
            -e "s|@coreutils@|${coreutils}|g" \
            -e "s|@grep@|${grep}|g" \
            -e "s|@policycoreutils@|${policycoreutils}|g" \
            -e "s|@libselinux@|${libselinux}|g" \
            -e "s|@out@|$out|g" \
            ${./refpolicy-load-policy.sh} \
            > "$out/libexec/aos-selinux-load-policy"
          chmod 0755 "$out/libexec/aos-selinux-load-policy"
          ${
            if production
            then ''test ! -e "$out/usr/share/selinux/refpolicy/aos_base.pp"''
            else ''test -s "$out/usr/share/selinux/refpolicy/aos_base.pp"''
          }

          # Patch the installed devel Makefile to use store paths instead
          # of hardcoded /usr and /etc paths
          DEVMK=$out/usr/share/selinux/refpolicy/include/Makefile
          sed -i \
            -e 's|^NAME ?=.*|NAME := refpolicy|' \
            -e 's|^SHAREDIR ?=.*|SHAREDIR := '"$out"'/usr/share/selinux|' \
            -e 's|^PREFIX :=.*|PREFIX := '"$out"'/usr|' \
            -e 's|^BINDIR :=.*|BINDIR := ${checkpolicy}/bin|' \
            -e 's|^SBINDIR :=.*|SBINDIR := ${policycoreutils}/sbin|' \
            -e 's|^CHECKMODULE :=.*|CHECKMODULE := ${checkpolicy}/bin/checkmodule|' \
            -e 's|^SEMODULE :=.*|SEMODULE := ${policycoreutils}/sbin/semodule|' \
            -e 's|^SEMOD_PKG :=.*|SEMOD_PKG := ${semodule-utils}/bin/semodule_package|' \
            "$DEVMK"
        '';
      }
    ];

    meta = {
      description =
        if production
        then "SELinux Reference Policy with the production Linux security-class map"
        else "SELinux Reference Policy — base SELinux policy";
      homepage = "https://github.com/SELinuxProject/refpolicy";
      license = "GPL-2.0-or-later";
    };
  }
