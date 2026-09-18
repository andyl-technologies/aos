##! autogen — Automated text and program generation
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  gnumake,
  autoconf,
  automake,
  pkg-config,
  perl,
  which,
  file,
  gc,
  gmp,
  guile,
  libffi,
  libatomic_ops,
  libunistring,
  libxcrypt,
  libxml2,
  zlib,
}: let
  version = "5.18.16";
  isLinuxCross = stdenv.isCross && stdenv.hostPlatform.isLinux;
  guile3Patch = fetchurl {
    urls = [
      "https://gitweb.gentoo.org/repo/gentoo.git/plain/sys-devel/autogen/files/autogen-5.18.16-guile-3.patch?id=43bcc61c56a5a7de0eaf806efec7d8c0e4c01ae7"
    ];
    hash = "sha256-LCcZZBrxAx//5G3qcS6H/RmJUa2Qn2UlbP5uYYeHnSk=";
  };
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "autogen";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "AutoGen expands the template to the fixed qualification line.";
        "files" = {
          "probe.def" = "AutoGen Definitions;\nanswer = \"qualified\";\n";
          "probe.tpl" = "[+ AutoGen5 template +]\n[+ answer +]\n";
        };
        "input" = "An AutoGen definition and template that expand one named value.";
        "operation" = "Render the definition through the packaged AutoGen interpreter.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/autogen\", \"-T\", \"probe.tpl\", \"probe.def\"], capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout.strip() == \"qualified\"\nprint(\"autogen operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "autogen operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "AutoGen rejects the invalid definition syntax.";
        "files" = {
          "probe.def" = "AutoGen Definitions;\nanswer = {\n";
          "probe.tpl" = "[+ AutoGen5 template +]\n[+ answer +]\n";
        };
        "input" = "An AutoGen definition with an unterminated aggregate value.";
        "operation" = "Render the malformed definition.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/autogen\", \"-T\", \"probe.tpl\", \"probe.def\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"autogen rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "autogen rejected invalid input\n";
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
        "https://ftp.gnu.org/gnu/autogen/rel${version}/autogen-${version}.tar.xz"
      ];
      hash = "sha256-+KE0ZrSPqjupn+F6Bp5xyasAbZsc+r5pn4xgpH1btJo=";
    };

    buildDeps = [gnumake autoconf automake pkg-config perl which file];
    # AutoGen's libtool link includes Guile's public libraries directly in the
    # executable's DT_NEEDED set. Declare them here so the scrub phase retains
    # the corresponding RPATH entries instead of treating them as build-only
    # transitive references.
    runtimeDeps =
      [gc gmp guile libffi libunistring libxcrypt libxml2 zlib]
      ++ lib.optionals isLinuxCross [libatomic_ops gnumake];
    propagatedDeps =
      [gc gmp guile libffi libunistring libxcrypt libxml2 zlib]
      ++ lib.optionals isLinuxCross [libatomic_ops];

    # Output specifications end in the classic struct-hack member
    # `char os_sfx[1]`, with the allocation extended for the actual suffix.
    # Strict level 3 makes fortify treat that member as exactly one byte and
    # abort valid writes while opening generated outputs.  Level 1 preserves
    # the intended trailing-array convention while retaining fortify3 and the
    # remaining hardening flags.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd autogen-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${guile3Patch}
          patch -p1 < ${./autogen-patches/0001-handle-overlapping-path-copies.patch}
          patch -p1 < ${./autogen-patches/0002-fix-sprintf-buffer-sizes.patch}
          patch -p1 < ${./autogen-patches/0003-fix-definition-buffer-growth.patch}
          patch -p1 < ${./autogen-patches/0004-remove-unused-enum-counter.patch}
          sed -i 's|/usr/bin/file|${file}/bin/file|g' configure config/libtool.m4
          ${lib.optionalString isLinuxCross ''
            # The error test already removes native abort notices. Normalize
            # the execution wrapper's notice while retaining error assertions.
            patch -p1 < ${./autogen-patches/0005-normalize-emulator-abort-notice.patch}

            # Linux target programs run through the configured execution
            # wrapper. Use the just-built generators for documentation and
            # tests instead of searching PATH for a pre-existing AutoGen.
            sed -i \
              -e '/^  AGexe=/c\  AGexe=$ag_top_builddir/agen5/$AGnam' \
              -e '/^  GDexe=/c\  GDexe=$ag_top_builddir/getdefs/$GDnam' \
              -e '/^  CLexe=/c\  CLexe=$ag_top_builddir/columns/$CLnam' \
              configure configure.ac

            # make-gperf invokes this embedded path after installation, so it
            # must identify the target make rather than the native build tool.
            sed -i 's|mk=`set -- $(MAKE) ; command -v $$1`|mk=${gnumake}/bin/make|' \
              agen5/Makefile.am agen5/Makefile.in
          ''}'';
      }
      {
        name = "configure";
        script =
          lib.optionalString isLinuxCross ''
            # Upstream either aborts or disables these libc features when it
            # cannot execute target programs during cross configuration.
            export ag_cv_run_strcspn=yes
            export ag_cv_run_uname_syscall=yes
            export libopts_cv_with_libregex=yes
            export libopts_cv_run_realpath=yes
            export libopts_cv_run_strftime=yes
            export libopts_cv_run_fopen_binary=yes
            export libopts_cv_run_fopen_text=yes
          ''
          + ''
            export MAN_PAGE_DATE=1970-01-01
            # Several installed helper programs link the in-tree libopts via
            # libtool. Give those helpers a final-store RPATH in addition to the
            # temporary build-tree path that libtool records.
            export LDFLAGS="$LDFLAGS -Wl,-rpath,$out/lib"
            ./configure $configureFlags \
              --prefix="$out" \
              --disable-dependency-tracking \
              --with-libxml2=${libxml2} \
              --with-libxml2-cflags=-I${libxml2}/include/libxml2 \
              --enable-timeout=78 \
              CFLAGS=-D_FILE_OFFSET_BITS=64
          '';
      }
      {
        name = "build";
        script = ''
          mkdir -p .aos-autotools
          ln -s ${automake}/bin/aclocal .aos-autotools/aclocal-1.16
          ln -s ${automake}/bin/automake .aos-autotools/automake-1.16
          export PATH="$PWD/.aos-autotools:$PATH"
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          if ! make -j"$NIX_BUILD_CORES" check; then
            find . -name test-suite.log -exec cat {} \;
            exit 1
          fi
        '';
      }
      {
        name = "install";
        script = ''
          make install
          "$out/bin/autogen" --version

          # AutoGen's timeout watcher can briefly retain the installed
          # executable after the generator exits. Wait until it releases the
          # file so the following reference scrub can safely rewrite it.
          attempts=0
          while ! : >> "$out/bin/autogen"; do
            attempts=$((attempts + 1))
            if [ "$attempts" -ge 30 ]; then
              echo "installed autogen executable remained busy" >&2
              exit 1
            fi
            sleep 1
          done
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-autogen";
        tool = self;
        command = "autogen --version && columns --version";
      };
    };

    meta = {
      description = "Automated text and program generation tool";
      homepage = "https://www.gnu.org/software/autogen/";
      license = "GPL-3.0-or-later AND LGPL-3.0-or-later";
      mainProgram = "autogen";
    };
  }
