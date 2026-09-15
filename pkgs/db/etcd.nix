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
    pname = "etcd";
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

    abilities = ./_etcd-config/module.nix;

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
          export GOCACHE=$TMPDIR/go-cache
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
      evalConfig = etcdConfig:
        lib.evalModules {
          modules = [
            ../../modules/abilities/default.nix
            {
              options.assertions = lib.mkOption {
                type = lib.types.listOf lib.types.attrs;
                default = [];
                contributable = true;
              };
              aos.abilities.environment = {
                authority = "deployment";
                key = "etcd-test";
                stage = "host";
              };
              etcd = etcdConfig;
            }
          ];
          packageModules = [
            {
              name = "etcd";
              module.imports = [./_etcd-config/module.nix];
            }
          ];
          inherit lib;
        };
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      evaluated = evalConfig {
        enable = true;
        name = "node-a";
        client = {
          listenUrls = ["http://127.0.0.1:12379"];
          advertiseUrls = ["http://127.0.0.1:12379"];
        };
        peer = {
          listenUrls = ["http://127.0.0.1:12380"];
          advertiseUrls = ["http://127.0.0.1:12380"];
        };
        cluster.members.node-a.peerUrls = ["http://127.0.0.1:12380"];
        storage = {
          quotaBackendBytes = 104857600;
          snapshotCount = 1000;
        };
      };
      invalidMember = evalConfig {
        name = "missing";
        cluster.members.node-a.peerUrls = ["http://127.0.0.1:2380"];
      };
      invalidTls = evalConfig {
        client = {
          listenUrls = ["https://127.0.0.1:2379"];
          advertiseUrls = ["https://127.0.0.1:2379"];
          tls.enable = true;
        };
      };
      invalidDuplicate = evalConfig {
        client.listenUrls = [
          "http://127.0.0.1:2379"
          "http://127.0.0.1:2379"
        ];
      };
      abilities = evaluated.config.aos.abilities;
      requests = builtins.attrNames abilities.requests;
      configurationSource = abilities.requests."etcd:server-configuration".parameters.source;
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
      contractHolds =
        assertionsHold evaluated
        && !assertionsHold invalidMember
        && !assertionsHold invalidTls
        && !assertionsHold invalidDuplicate
        && builtins.elem "etcd:main-lifecycle" requests
        && builtins.elem "etcd:main-dependencies" requests
        && builtins.elem "etcd:main-readiness" requests
        && builtins.elem "etcd:server-configuration" requests
        && configurationSource.kind == "structured-value"
        && configurationSource.format == "json"
        && !(lib.hasInfix "/var/lib/aos-pkg-etcd" (builtins.toJSON configurationSource));
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

      ability-module-contract =
        if contractHolds
        then
          pkgs.runCommand "db-etcd-ability-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS >"$out/result"
          ''
        else throw "the etcd ability module contract checks failed";
    };

    meta = {
      description = "etcd — distributed reliable key-value store";
      homepage = "https://etcd.io";
      license = "Apache-2.0";
    };
  }
