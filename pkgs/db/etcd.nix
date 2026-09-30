##! etcd — Distributed key-value store
{
  lib,
  mkDerivation,
  fetchurl,
  fetchGoModules,
  buildPackages,
  gnumake,
  go,
  stdenv,
  service-management,
  aos-filesystem-provider,
}: let
  version = "3.7.1";
  src = fetchurl {
    urls = [
      "https://github.com/etcd-io/etcd/archive/v${version}/etcd-${version}.tar.gz"
    ];
    hash = "sha256-lTUqlv+x2S33e1vOK7I5BG+pTNmdyDn/fuz9yYNBZjc=";
  };

  serverModules = fetchGoModules {
    inherit src;
    name = "etcd-server-modules";
    sourceRoot = "etcd-${version}/server";
    hash = "sha256-P53Cgg4phztWZefOtu89XsoUPHiO7kRaYFYXPn0KpfE=";
  };

  etcdctlModules = fetchGoModules {
    inherit src;
    name = "etcdctl-modules";
    sourceRoot = "etcd-${version}/etcdctl";
    hash = "sha256-P53Cgg4phztWZefOtu89XsoUPHiO7kRaYFYXPn0KpfE=";
  };

  etcdutlModules = fetchGoModules {
    inherit src;
    name = "etcdutl-modules";
    sourceRoot = "etcd-${version}/etcdutl";
    hash = "sha256-P53Cgg4phztWZefOtu89XsoUPHiO7kRaYFYXPn0KpfE=";
  };
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };
    pname = "etcd";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Etcd reports version 3.7.1 without opening a listener.";
        "files" = {};
        "input" = "The packaged etcd server and data-file utility suite.";
        "operation" = "Request the server's version and confirm its semantic version.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/etcd\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"etcd Version: 3.7.1\" in result.stdout\nprint(\"etcd operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "etcd operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Etcdutl rejects the nonexistent snapshot.";
        "files" = {};
        "input" = "A path that is not an etcd snapshot database.";
        "operation" = "Inspect the malformed path with etcdutl snapshot status.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/etcdutl\", \"snapshot\", \"status\", \"absent.db\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"etcd rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "etcd rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    inherit src;

    # The published Go package is Darwin-hosted in a cross package set and
    # cannot execute on the Linux builder.  Go's native compiler emits the
    # selected Darwin target directly.
    buildDeps =
      if stdenv.isCross
      then [buildPackages.go]
      else [gnumake go];
    runtimeDeps = [];

    module = ./_etcd-config;
    moduleDeps = [service-management aos-filesystem-provider];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd etcd-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOCACHE="''${GOCACHE:-$TMPDIR/go-cache}"
          export CGO_ENABLED=0
          export GOPROXY=off
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          mkdir -p "$GOCACHE" bin

          cd server
          GOPATH="${serverModules}" GOFLAGS="-trimpath -mod=readonly" \
            go build -ldflags "-s -w \
              -X go.etcd.io/etcd/api/v3/version.GitSHA=v${version}" \
            -o ../bin/etcd .
          cd ..

          cd etcdctl
          GOPATH="${etcdctlModules}" GOFLAGS="-trimpath -mod=readonly" \
            go build -ldflags "-s -w" -o ../bin/etcdctl .
          cd ..

          cd etcdutl
          GOPATH="${etcdutlModules}" GOFLAGS="-trimpath -mod=readonly" \
            go build -ldflags "-s -w" -o ../bin/etcdutl .
          cd ..
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 bin/etcd bin/etcdctl bin/etcdutl $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: let
      nativeTests = import ./_etcd-config/native-tests.nix {inherit lib self;};
      runtimeConfig = builtins.toFile "etcd-runtime-check.json" (builtins.toJSON {
        name = "node-a";
        "data-dir" = "/var/lib/etcd-check";
        "listen-client-urls" = "http://127.0.0.1:12379";
        "advertise-client-urls" = "http://127.0.0.1:12379";
        "listen-peer-urls" = "http://127.0.0.1:12380";
        "initial-advertise-peer-urls" = "http://127.0.0.1:12380";
        "initial-cluster" = "node-a=http://127.0.0.1:12380";
        "initial-cluster-state" = "new";
        "initial-cluster-token" = "aos-etcd-check";
      });
    in {
      version = testing.mkToolCheck {
        pname = "tool-etcd";
        tool = self;
        command = "etcd --version";
      };

      runtime = testing.mkVMTest {
        name = "db-etcd-runtime";
        rootfsDeps = [self runtimeConfig pkgs.iproute2];
        testScript = ''
          ${pkgs.iproute2}/sbin/ip link set lo up
          mkdir -p /var/lib/etcd-check
          etcd --config-file ${runtimeConfig} >/tmp/etcd.log 2>&1 &
          ETCD_PID=$!
          trap 'kill "$ETCD_PID" 2>/dev/null || true' EXIT

          READY=false
          for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if etcdctl --endpoints=http://127.0.0.1:12379 endpoint health >/dev/null 2>&1; then
              READY=true
              break
            fi
            sleep 1
          done
          if [ "$READY" != true ]; then
            cat /tmp/etcd.log >&2
            exit 1
          fi

          etcdctl --endpoints=http://127.0.0.1:12379 put aos-check healthy
          test "$(etcdctl --endpoints=http://127.0.0.1:12379 get aos-check --print-value-only)" = healthy
          kill "$ETCD_PID"
          wait "$ETCD_PID" || true
          trap - EXIT

          printf '%s\n' '{"unknown-setting":true}' >/tmp/etcd-invalid.json
          if etcd --config-file /tmp/etcd-invalid.json >/tmp/etcd-invalid.log 2>&1; then
            echo "etcd accepted an unknown configuration field" >&2
            exit 1
          fi
          echo "==> etcd runtime configuration and lifecycle: PASS"
        '';
      };

      native-module-contract =
        if builtins.all (value: value) (builtins.attrValues nativeTests)
        then
          pkgs.runCommand "db-etcd-native-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS >"$out/result"
          ''
        else throw "the etcd native module contract checks failed";
    };

    meta = {
      description = "etcd — distributed reliable key-value store";
      homepage = "https://etcd.io";
      license = "Apache-2.0";
    };
  }
