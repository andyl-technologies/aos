##! Go 1.4 — first Go bootstrap stage, compiled from C source
{
  mkDerivation,
  fetchgit,
  stdenv,
  buildPackages,
}: let
  pname = "go-1_4";
  version = "1.4-bootstrap-20260507";

  # The upstream bootstrap archive contains compiled debugger and race-test
  # fixtures. Sparse Git checkout excludes their blobs before fetching source.
  src = fetchgit {
    url = "https://go.googlesource.com/go";
    ref = "release-branch.go1.4";
    rev = "6dea79a07ad81332253a1ea1d52bbdbb50a3ed2f";
    hash = "sha256-2WPPIqtrVDQfOenYwRLoZkFvu4Tp6UjUpXAVn0079y8=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/src/"
      "/include/"
      "/lib/"
      "/VERSION"
      "/LICENSE"
      "/PATENTS"
      "!/src/debug/dwarf/testdata/*"
      "!/src/debug/elf/testdata/*"
      "!/src/debug/macho/testdata/*"
      "!/src/debug/pe/testdata/*"
      "!/src/debug/plan9obj/testdata/*"
      "!/src/runtime/race/*.syso"
      "!/src/archive/zip/testdata/*"
      "!/lib/time/zoneinfo.zip"
    ];
  };

  # Legacy C tools retain build-compiler include paths in DWARF. Keep Go's
  # custom ELF metadata while removing debug sections from those tools only.
  stripCrossBootstrapDebug =
    if stdenv.isCross
    then ''
      for tool in 6a 6c 6g 6l; do
        "$OBJCOPY" --strip-debug "$out/pkg/tool/${stdenv.hostPlatform.go.os}_${stdenv.hostPlatform.go.arch}/$tool"
      done
    ''
    else "";
in
  if stdenv.hostPlatform.isDarwin
  then
    import ./_go-darwin.nix {
      inherit mkDerivation pname version src stdenv;
      nativeGo = buildPackages.go-1_4;
      nativeCc = buildPackages.cc;
      legacyCBootstrap = true;
      description = "Go 1.4 bootstrap — Darwin-hosted toolchain built with native Go 1.4";
    }
  else
    mkDerivation {
      inherit pname version src;

      buildDeps = [
        buildPackages.coreutils
        buildPackages.findutils
        buildPackages.sed
        buildPackages.zip
        buildPackages.tzdata
      ];
      runtimeDeps = [];
      dontStrip = true; # Go runtime metadata in custom ELF sections

      # The 2017-era Go 1.4 C bootstrap predates modern glibc hardening: its
      # Plan9-style p9jmp_buf is sized smaller than glibc's sigjmp_buf, so the
      # fortified __longjmp_chk aborts the dist tool with "buffer overflow
      # detected". Build the bootstrap compiler without injected hardening.
      hardeningDisable = ["all"];

      phases = [
        {
          name = "unpack";
          script = ''
            mkdir go
            cp -a ${src}/. go/
            chmod -R u+w go
            cd go
          '';
        }
        {
          name = "build";
          script = ''
            export GOROOT_FINAL=$out
            export GOCACHE=$TMPDIR/go-cache
            export CGO_ENABLED=0

            # Go 1.4 defines bool as a C typedef. GCC 15 and newer default to
            # C23, where bool is a keyword, so keep this bootstrap in C17.
            export CC="''${CC:-gcc} -std=gnu17"

            cd src
            bash make.bash
            cd ..
          '';
        }
        {
          name = "install";
          script =
            ''
              mkdir -p $out/bin $out/src $out/pkg
              cp -a bin/* $out/bin/
              cp -a src/* $out/src/
              cp -a pkg/* $out/pkg/

              # Dist's C object archives are bootstrap intermediates. The
              # installed compiler and linker tools do not read them.
              rm -rf "$out/pkg/obj"

              # Supply Go's portable timezone fallback from AOS-built tzdata.
              mkdir -p "$out/lib/time"
              (
                cd ${buildPackages.tzdata}/share/zoneinfo
                # Go 1.4's ZIP reader only supports stored (method 0) entries.
                find -L . -type f -print | sort | sed 's|^./||' | \
                  zip -X -0 -q "$out/lib/time/zoneinfo.zip" -@
              )
            ''
            + stripCrossBootstrapDebug;
        }
      ];

      meta = {
        description = "Go 1.4 bootstrap — compiled from C source";
        homepage = "https://go.dev";
        license = "BSD-3-Clause";
      };
    }
