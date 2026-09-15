##! tailscale — Mesh VPN client and coordination daemon
{
  lib,
  mkDerivation,
  fetchurl,
  fetchGoModules,
  buildPackages,
  getent,
  iproute2,
  iptables,
  procps-ng,
}: let
  # Newer releases require a Go patch release newer than the self-hosted AOS
  # compiler. Keep the newest release whose declared toolchain floor is met.
  version = "1.102.3";
  src = fetchurl {
    urls = ["https://github.com/tailscale/tailscale/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-DpTZYcMc59M+i3zkrG/b7IPuVlh4Tu1p63/OMAcp1xc=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-tZaxUYDEj3xJ2jxhQTv970MhwK+3cM7nQZunae2nW2s=";
  };
in
  mkDerivation {
    pname = "tailscale";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The client reports a nonempty semantic release version and its Go toolchain.";
        "files" = {};
        "input" = "The installed Tailscale client build metadata.";
        "operation" = "Read the client, long, and Go version tuple without contacting tailscaled.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/tailscale\", \"version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"long version:\" in result.stdout and \"go version:\" in result.stdout\nprint(\"tailscale operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "tailscale operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The Tailscale client rejects the malformed boolean value.";
        "files" = {};
        "input" = "A status request with an invalid boolean value for JSON output.";
        "operation" = "Parse the status flags before connecting to the daemon socket.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/tailscale\", \"--socket\", \"missing.sock\", \"status\", \"--json=qualification-invalid\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"invalid boolean value\" in result.stderr\n\nsys.stderr.write(\"tailscale rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "tailscale rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    abilities = ./_tailscale/module.nix;

    buildDeps = [buildPackages.go];
    runtimeDeps = [getent iproute2 iptables procps-ng];
    propagatedDeps = [];
    disallowedReferences = [buildPackages.go goModules];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd tailscale-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export GOPATH="${goModules}"
          export GOCACHE="$TMPDIR/go-cache"
          export GOFLAGS="-trimpath -mod=readonly"
          export GOPROXY=off
          export CGO_ENABLED=0
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          mkdir -p "$GOCACHE"
        '';
      }
      {
        name = "build";
        script = ''
          versionFlags="-s -w -X tailscale.com/version.longStamp=${version} -X tailscale.com/version.shortStamp=${version}"
          go build -tags ts_include_cli -ldflags "$versionFlags" -o tailscaled ./cmd/tailscaled
          go build -ldflags "$versionFlags" -o derper ./cmd/derper
          go build -ldflags "$versionFlags" -o derpprobe ./cmd/derpprobe
          go build -ldflags "$versionFlags" -o get-authkey ./cmd/get-authkey
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          install -m 755 tailscaled derper derpprobe get-authkey "$out/bin/"
          ln -s tailscaled "$out/bin/tailscale"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-tailscale";
        tool = self;
        command = "tailscale version && tailscaled --version && derper --help >/dev/null";
      };
    };

    meta = {
      description = "Mesh VPN client, daemon, and DERP relay";
      homepage = "https://tailscale.com/";
      license = "BSD-3-Clause";
      mainProgram = "tailscale";
    };
  }
