##! Go 1.4 — first Go bootstrap stage, compiled from C source
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
}: let
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64"]; os = ["darwin"];}];
    target = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64"]; os = ["darwin"];}];
    role = "public-package";
  };
  pname = "go-1_4";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The program prints the strings in lexical order.";
      "files" = {
        "main.go" = "package main\n\nimport (\n    \"fmt\"\n    \"sort\"\n)\n\nfunc main() {\n    values := []string{\"gamma\", \"alpha\", \"beta\"}\n    sort.Strings(values)\n    fmt.Println(values)\n}\n";
      };
      "input" = "A Go program that sorts three strings.";
      "operation" = "Compile and run the program with the packaged Go toolchain.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/go"
            "run"
            "@work@/primary/main.go"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "[alpha beta gamma]\n";
          };
          "timeout_seconds" = 120;
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The Go parser rejects the source with status 1.";
      "files" = {
        "invalid.go" = "package main\nfunc main() { value := ; _ = value }\n";
      };
      "input" = "A Go program with a missing expression in a declaration.";
      "operation" = "Compile the malformed program with the packaged Go toolchain.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/go"
            "run"
            "@work@/bad-input/invalid.go"
          ];
          "exit_code" = 1;
          "observes_rejection" = true;
          "stdout" = {
            "exact" = "";
          };
          "timeout_seconds" = 120;
        }
      ];
    };
  };

  version = "1.4-bootstrap-20171003";

  src = fetchurl {
    urls = [
      "https://go.dev/dl/go1.4-bootstrap-20171003.tar.gz"
    ];
    hash = "sha256-9P9bXrOjyuHJk3I/PqtRnFuuGIZrXl+W/hEC8MtcPlI=";
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
      inherit mkDerivation pname version src stdenv qualification platformSupport;
      nativeGo = buildPackages.go-1_4;
      nativeCc = buildPackages.cc;
      legacyCBootstrap = true;
      description = "Go 1.4 bootstrap — Darwin-hosted toolchain built with native Go 1.4";
    }
  else
    mkDerivation {
      inherit pname version src qualification platformSupport;

      buildDeps = [];
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
            tar xf $src
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
