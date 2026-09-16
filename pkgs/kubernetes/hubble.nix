##! Hubble — Cilium observability CLI
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "1.19.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "hubble";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Hubble returns a Bash function wired to its completion endpoint.";
        "files" = {};
        "input" = "A request for Hubble's Bash completion program.";
        "operation" = "Generate the completion program without contacting Hubble Relay.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/hubble\", \"completion\", \"bash\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"__start_hubble\" in result.stdout and \"complete -o default\" in result.stdout, (result.returncode, result.stdout, result.stderr)\nprint(\"hubble operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "hubble operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Hubble rejects the unknown command.";
        "files" = {};
        "input" = "A Hubble invocation naming an unknown top-level command.";
        "operation" = "Parse the unsupported command without contacting Hubble Relay.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/hubble\", \"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"hubble rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "hubble rejected invalid input\n";
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
        "https://github.com/cilium/hubble/archive/v${version}/hubble-${version}.tar.gz"
      ];
      hash = "sha256-gujQYujyz+7K7aGfMANQ1rRT1tFYTyER9qd2NyKZQ2Y=";
    };

    # Use the Linux-hosted compiler when producing Darwin commands.  The
    # target Go distribution is a Mach-O runtime artifact and cannot execute
    # during this build.
    buildDeps = [buildPackages.go];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd hubble-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOPROXY=off
          export GOFLAGS="-trimpath -mod=vendor"
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          mkdir -p "$GOPATH" "$GOCACHE"

          go build -ldflags "-s -w \
            -X github.com/cilium/hubble/pkg/version.Version=v${version}" \
            -o hubble .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 hubble $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-hubble";
        tool = self;
        command = "hubble version";
      };
    };

    meta = {
      description = "Hubble — Cilium network observability CLI";
      homepage = "https://github.com/cilium/hubble";
      license = "Apache-2.0";
    };
  }
