##! Builds a Darwin-hosted Go distribution with a Linux-native Go compiler.
##!
##! Go's build is unusually friendly to a Canadian cross: once a matching
##! native distribution has generated the version and build-configuration
##! sources, that native `go` command can compile every command and internal
##! tool as a pure-Go Mach-O executable.  No target executable is run here.
{
  mkDerivation,
  pname,
  version,
  src,
  nativeGo,
  nativeCc ? null,
  legacyCBootstrap ? false,
  stdenv,
  description,
}: let
  targetOs = stdenv.hostPlatform.go.os;
  targetArch = stdenv.hostPlatform.go.arch;
  toolDirectory = "${targetOs}_${targetArch}";
  nativeToolDirectory = "${stdenv.buildPlatform.go.os}_${stdenv.buildPlatform.go.arch}";
  legacyToolChar =
    if targetArch == "amd64"
    then "6"
    else throw "Go 1.4 Darwin bootstrap does not support ${targetArch}";
  legacyNativeCc =
    if legacyCBootstrap && nativeCc == null
    then throw "Go 1.4 Darwin bootstrap requires a native C compiler"
    else nativeCc;
in
  mkDerivation {
    inherit pname version src;

    buildDeps = [nativeGo];
    runtimeDeps = [];

    # Go binaries carry runtime metadata in object-file sections that generic
    # stripping does not understand well enough to preserve.
    dontStrip = true;

    phases = [
      {
        name = "unpack";
        script =
          if legacyCBootstrap
          then ''
            mkdir -p "$out"
            cp -a ${nativeGo}/. "$out"/
            chmod -R u+w "$out"

            # Go 1.4's installed native distribution omits the Plan 9 C
            # headers needed to rebuild its pre-Go compiler toolchain.
            # Restore only those canonical source assets and VERSION from
            # the same pinned release archive.
            tar xf $src -C "$out" --strip-components=1 \
              go/include go/lib go/VERSION
            cd "$out"
          ''
          else ''
            mkdir go
            cp -a ${nativeGo}/. go/
            chmod -R u+w go


            cd go
          '';
      }
      {
        name = "configure";
        script = ''
          # The native bootstrap records its Linux compiler in generated Go
          # sources.  A Darwin-hosted go command must instead use the compiler
          # supplied by its eventual Darwin environment.  Cover both the old
          # Go 1.4 constants and the modern generated helper functions.
            for default_cc in $(find src -name zdefaultcc.go -type f); do
            sed -i \
              -e 's|^const defaultCC = .*|const defaultCC = "clang"|' \
              -e 's|^const defaultCXX = .*|const defaultCXX = "clang++"|' \
              -e '/^func DefaultCC(/,/^}/s|^[[:space:]]*return ".*"|\treturn "clang"|' \
              -e '/^func DefaultCXX(/,/^}/s|^[[:space:]]*return ".*"|\treturn "clang++"|' \
              -e '/^func defaultCC(/,/^}/s|^[[:space:]]*return ".*"|\treturn "clang"|' \
              -e '/^func defaultCXX(/,/^}/s|^[[:space:]]*return ".*"|\treturn "clang++"|' \
                "$default_cc"
            done

            ${
            if legacyCBootstrap
            then ''
              # Generated Go 1.4 sources retain the native bootstrap GOROOT.
              # The target commands and runtime archive must describe their
              # final Darwin distribution instead of keeping that Linux root.
              find src -type f -exec sed -i \
                "s|${nativeGo}|$out|g" {} +
            ''
            else ""
          }
        '';
      }
      {
        name = "build";
        script = ''
          export GOROOT="$PWD"
          export GOROOT_FINAL="$out"
          export GOCACHE="$TMPDIR/go-cache"
          export GOENV=off
          export GOOS=${targetOs}
          export GOARCH=${targetArch}
          export CGO_ENABLED=0
          # Remove the ephemeral Linux GOROOT from the Darwin commands' DWARF
          # and pclntab. The installed toolchain is relocatable and discovers
          # its real GOROOT from the executable path on Darwin.
          export GOFLAGS=-trimpath

          ${
            if legacyCBootstrap
            then ''
                  # Go 1.4 predates the compiler's rewrite in Go. Build a second,
                  # Linux-runnable dist driver whose build identity is Darwin, and
                  # use it only to cross-compile the canonical C compiler/linker
                  # programs. Target binaries are never executed during the build.
                  cp -a src/cmd/dist "$TMPDIR/dist-cross"
                  chmod -R u+w "$TMPDIR/dist-cross"
                  sed -i \
                    -e 's/gohostos = "linux";/gohostos = "darwin";/' \
                    -e 's/-mmacosx-version-min=10\.6/-mmacosx-version-min=11.0/' \
                    "$TMPDIR/dist-cross/unix.c" \
                    "$TMPDIR/dist-cross/build.c"
              AOS_HARDENING_ENABLE= NIX_CFLAGS_COMPILE= NIX_LDFLAGS= \
                  ${legacyNativeCc}/bin/cc -O2 \
                  -I"$TMPDIR/dist-cross" \
                    -DGOROOT_FINAL=\"$out\" \
                    -o "$TMPDIR/dist-cross-tool" \
                    "$TMPDIR/dist-cross"/*.c

                  mkdir -p \
                    "pkg/obj/${toolDirectory}" \
                    "pkg/tool/${toolDirectory}"

                  # The native dist generator emits the target runtime's assembly
                  # ABI headers without trying to execute target code. It rewrites
                  # zversion.go, so correct that generated GOROOT before the target
                  # runtime archive and commands are rebuilt below.
                  (cd src && \
                    "../pkg/tool/${nativeToolDirectory}/dist" install runtime)
                  grep -F -q ${nativeGo} src/runtime/zversion.go
                  sed -i "s|${nativeGo}|$out|g" src/runtime/zversion.go

                  for directory in \
                    lib9 libbio liblink cmd/cc cmd/gc \
                    cmd/${legacyToolChar}l cmd/${legacyToolChar}a \
                    cmd/${legacyToolChar}c cmd/${legacyToolChar}g; do
                    "$TMPDIR/dist-cross-tool" install "$directory"
                  done
            ''
            else ""
          }

          # With no GOBIN override, cmd/go installs ordinary commands beneath
          # bin/<goos>_<goarch> and compiler tools beneath
          # pkg/tool/<goos>_<goarch>.  That is precisely the layout expected
          # when the resulting Darwin go command runs on its host.
          ${nativeGo}/bin/go install -a std
          ${nativeGo}/bin/go install -a cmd/...

          test -x "bin/${toolDirectory}/go"
          test -x "bin/${toolDirectory}/gofmt"
          test -d "pkg/tool/${toolDirectory}"

          for executable in \
            "bin/${toolDirectory}/go" \
            "bin/${toolDirectory}/gofmt" \
            "pkg/tool/${toolDirectory}"/*; do
            "$OBJDUMP" --macho --private-header "$executable" >/dev/null
          done
        '';
      }
      {
        name = "install";
        script =
          if legacyCBootstrap
          then ''
            # Building from the final store path preserves useful source
            # locations without Go 1.4's unavailable -trimpath support.
            # Replace the copied Linux bootstrap commands with the target
            # commands and remove every remaining native package/tool tree.
            cp -a "bin/${toolDirectory}/." "$out/bin/"
            rm -rf \
                "$out/bin/${toolDirectory}" \
                "$out/pkg/${nativeToolDirectory}" \
                "$out/pkg/obj" \
                "$out/pkg/tool/${nativeToolDirectory}" \
              "$out/nix-support"

            # Go ships ELF and multi-architecture Mach-O executables as debugger
            # and profiler test fixtures. They are data, but upstream gives
            # several of them an executable bit. Preserve the fixtures while
            # preventing output validation from treating them as hosted tools.
            find "$out/src" -type f -perm -u+x | while IFS= read -r fixture; do
              magic=$(od -An -tx1 -N4 "$fixture" 2>/dev/null | tr -d ' \n')
              case "$magic" in
                7f454c46 | cefaedfe | feedface | cffaedfe | feedfacf | cafebabe | bebafeca)
                  chmod a-x "$fixture"
                  ;;
              esac
            done
          ''
          else ''
              mkdir -p "$out/bin" "$out/pkg/tool"

              cp -a "bin/${toolDirectory}/." "$out/bin/"
              cp -a "pkg/tool/${toolDirectory}" "$out/pkg/tool/"
              cp -a src "$out/"

              if [ -d "pkg/${toolDirectory}" ]; then
                cp -a "pkg/${toolDirectory}" "$out/pkg/"
              fi
              if [ -d pkg/include ]; then
                cp -a pkg/include "$out/pkg/"
              fi
              for directory in api doc lib misc test; do
                if [ -d "$directory" ]; then
                  cp -a "$directory" "$out/"
                fi
              done
              for file in CONTRIBUTING.md LICENSE PATENTS README.md SECURITY.md VERSION go.env; do
                if [ -f "$file" ]; then
                  cp -a "$file" "$out/"
                fi
              done

            # Go ships ELF and multi-architecture Mach-O executables as debugger
            # and profiler test fixtures. They are data, but upstream gives
            # several of them an executable bit. Preserve the fixtures while
            # preventing output validation from treating them as hosted tools.
            find "$out/src" -type f -perm -u+x | while IFS= read -r fixture; do
              magic=$(od -An -tx1 -N4 "$fixture" 2>/dev/null | tr -d ' \n')
              case "$magic" in
                7f454c46 | cefaedfe | feedface | cffaedfe | feedfacf | cafebabe | bebafeca)
                  chmod a-x "$fixture"
                  ;;
              esac
            done
          '';
      }
    ];

    meta = {
      inherit description;
      homepage = "https://go.dev";
      license = "BSD-3-Clause";
    };
  }
