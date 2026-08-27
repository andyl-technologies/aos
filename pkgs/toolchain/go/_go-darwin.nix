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
  stdenv,
  description,
}: let
  targetOs = stdenv.hostPlatform.go.os;
  targetArch = stdenv.hostPlatform.go.arch;
  toolDirectory = "${targetOs}_${targetArch}";
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
        script = ''
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
              "$default_cc"
          done
        '';
      }
      {
        name = "build";
        script = ''
          export GOROOT="$PWD"
          export GOCACHE="$TMPDIR/go-cache"
          export GOENV=off
          export GOOS=${targetOs}
          export GOARCH=${targetArch}
          export CGO_ENABLED=0
          # Remove the ephemeral Linux GOROOT from the Darwin commands' DWARF
          # and pclntab. The installed toolchain is relocatable and discovers
          # its real GOROOT from the executable path on Darwin.
          export GOFLAGS=-trimpath

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
        script = ''
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

          # Go ships ELF executables as debugger and profiler test fixtures.
          # They are data on Darwin, but upstream gives several of them an
          # executable bit. Preserve the fixtures while preventing generic
          # Darwin output validation from treating them as hosted programs.
          find "$out/src" -type f -perm -u+x | while IFS= read -r fixture; do
            magic=$(od -An -tx1 -N4 "$fixture" 2>/dev/null | tr -d ' \n')
            if [ "$magic" = 7f454c46 ]; then
              chmod a-x "$fixture"
            fi
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
