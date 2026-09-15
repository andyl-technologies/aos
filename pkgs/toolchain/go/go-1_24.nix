##! Go 1.24 — fifth Go bootstrap stage, built with Go 1.22
{
  lib,
  mkDerivation,
  fetchurl,
  go-1_22,
  stdenv,
  buildPackages,
}: let
  version = "1.24.13";
  src = fetchurl {
    urls = [
      "https://go.dev/dl/go${version}.src.tar.gz"
    ];
    hash = "sha256-Y5piBMJIaxN98etueO4+0Dj5h30OS1pGXnlqIVP4WNc=";
  };
in
  if stdenv.hostPlatform.isDarwin
  then
    import ./_go-darwin.nix {
      inherit mkDerivation version src stdenv;
      pname = "go-1_24";
      nativeGo = buildPackages.go-1_24;
      description = "Go 1.24 bootstrap — Darwin-hosted toolchain built with native Go 1.24";
    }
  else if stdenv.isCross
  then
    import ./_go-linux-cross.nix {
      inherit mkDerivation version src stdenv;
      pname = "go-1_24";
      nativeGo = buildPackages.go-1_24;
      description = "Go 1.24 bootstrap — cross-built Linux-hosted toolchain";
    }
  else
    mkDerivation {
      pname = "go-1_24";
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

      inherit version;

      inherit src;

      buildDeps = [go-1_22];
      runtimeDeps = [];
      dontStrip = true; # Go runtime metadata in custom ELF sections

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
            export GOROOT_BOOTSTRAP=${go-1_22}
            export GOROOT_FINAL=$out
            export GOCACHE=$TMPDIR/go-cache
            export CGO_ENABLED=0
            cd src
            bash make.bash
            cd ..
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p $out/bin $out/src $out/pkg
            cp -a bin/* $out/bin/
            cp -a src/* $out/src/
            cp -a pkg/* $out/pkg/
          '';
        }
      ];

      meta = {
        description = "Go 1.24 bootstrap — built with Go 1.22";
        homepage = "https://go.dev";
        license = "BSD-3-Clause";
      };
    }
