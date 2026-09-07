##! Builds a Linux-hosted Go distribution for another Linux architecture.
##!
##! A matching native Go distribution supplies the compiler that runs during
##! the build. It compiles the standard library, commands, and internal tools
##! for the selected target architecture without executing those target
##! binaries on the build machine.
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
          # The native distribution records its build-machine compiler in
          # generated sources. The target-hosted command must resolve the AOS
          # compiler wrapper from its eventual execution environment.
          for default_cc in $(find src -name zdefaultcc.go -type f); do
            sed -i \
              -e 's|^const defaultCC = .*|const defaultCC = "cc"|' \
              -e 's|^const defaultCXX = .*|const defaultCXX = "c++"|' \
              -e '/^func DefaultCC(/,/^}/s|^[[:space:]]*return ".*"|\treturn "cc"|' \
              -e '/^func DefaultCXX(/,/^}/s|^[[:space:]]*return ".*"|\treturn "c++"|' \
              -e '/^func defaultCC(/,/^}/s|^[[:space:]]*return ".*"|\treturn "cc"|' \
              -e '/^func defaultCXX(/,/^}/s|^[[:space:]]*return ".*"|\treturn "c++"|' \
              "$default_cc"
          done

          # The copied native distribution also records its ELF interpreter
          # in the linker configuration. Replace it before compiling the
          # target linker so cgo outputs use the selected target glibc.
          target_dynamic_linker=$(cat ${stdenv.cc}/nix-support/dynamic-linker)
          sed -i \
            "s|^const defaultGO_LDSO = .*|const defaultGO_LDSO = \`$target_dynamic_linker\`|" \
            src/internal/buildcfg/zbootstrap.go
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
          export GOFLAGS=-trimpath

          ${nativeGo}/bin/go install -a std
          ${nativeGo}/bin/go install -a cmd/...

          test -x "bin/${toolDirectory}/go"
          test -x "bin/${toolDirectory}/gofmt"
          test -d "pkg/tool/${toolDirectory}"

          for executable in \
            "bin/${toolDirectory}/go" \
            "bin/${toolDirectory}/gofmt" \
            "pkg/tool/${toolDirectory}"/*; do
            "$OBJDUMP" --file-headers "$executable" >/dev/null
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

          # Go ships executable-marked object files as debugger and profiler
          # fixtures. Keep the data while excluding it from hosted-tool scans.
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
