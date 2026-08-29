##! etcd — Distributed key-value store
{
  lib,
  mkDerivation,
  fetchurl,
  fetchGoModules,
  gnumake,
  go,
  writeShellScriptBin,
}: let
  version = "3.5.21";
  src = fetchurl {
    urls = [
      "https://github.com/etcd-io/etcd/archive/v${version}/etcd-${version}.tar.gz"
    ];
    hash = "sha256-dtf8r+T8yVf81FZxImuZLBbl9eckk13qnfAZCsKxNIE=";
  };

  serverModules = fetchGoModules {
    inherit src;
    name = "etcd-server-modules";
    sourceRoot = "etcd-${version}/server";
    hash = "sha256-WQERZkiUy6qjGtnLwdJBUEaX+JF55DjqZPnPIDSpK7A=";
  };

  etcdctlModules = fetchGoModules {
    inherit src;
    name = "etcdctl-modules";
    sourceRoot = "etcd-${version}/etcdctl";
    hash = "sha256-/14AOtsHbSHKpy7R2GsLxyaDGhqTHTVPEfA/IuwdEYc=";
  };

  etcdutlModules = fetchGoModules {
    inherit src;
    name = "etcdutl-modules";
    sourceRoot = "etcd-${version}/etcdutl";
    hash = "sha256-VpQYa5/CLyzE6vva78hahzKWqRVE3BB4nhHly9SnuXg=";
  };
  control = writeShellScriptBin "etcd-control" ''
    set -eu
    case "''${1:-}" in
      enabled)
        test "''${ETCD_ENABLED:-false}" = true
        ;;
      *)
        echo "usage: etcd-control enabled" >&2
        exit 64
        ;;
    esac
  '';
  credentialNames = [
    "client-certificate"
    "client-private-key"
    "client-trusted-ca"
    "peer-certificate"
    "peer-private-key"
    "peer-trusted-ca"
  ];
in
  mkDerivation {
    pname = "etcd";
    inherit version;
    inherit src;

    buildDeps = [
      gnumake
      go
    ];
    runtimeDeps = [control];

    expose = {
      units."etcd.service" = {
        description = "etcd distributed key-value store";
        after = ["network-online.target"];
        wants = ["network-online.target"];
        restartIfChanged = true;
        stopOnRemoval = true;
        serviceConfig = {
          Type = "notify";
          NotifyAccess = "all";
          DynamicUser = true;
          EnvironmentFile = "/etc/aos/packages/etcd/service.env";
          ExecCondition = "/bin/etcd-control enabled";
          ExecStart = "/bin/etcd --config-file /etc/aos/packages/etcd/etcd.json";
          Restart = "on-failure";
          RestartSec = "5s";
          StateDirectory = "aos-pkg-etcd";
          StateDirectoryMode = "0700";
          RuntimeDirectory = "aos-pkg-etcd";
          RuntimeDirectoryMode = "0750";
          LimitNOFILE = "1048576";
          UMask = "0077";
        };
      };

      config = {
        artifacts = [
          {
            name = "service";
            path = "/etc/aos/packages/etcd/service.env";
            format = "env";
            required = ["ETCD_ENABLED" "ETCD_CONFIG_GENERATION"];
            optional = [];
            units = ["etcd.service"];
            reload = "restart";
          }
        ];
        credentials =
          builtins.map (name: {
            inherit name;
            source = "/run/credstore/etcd/${name}";
            units = ["etcd.service"];
            encrypted = false;
            optional = true;
          })
          credentialNames;
      };

      permissions = {
        network = "host";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = "/etc/aos/packages/etcd/etcd.json";
            mode = "read-only";
          }
        ];
        syscalls = "restricted";
        security-label = "aos-pkg-etcd";
      };
    };

    configModule = {
      src = ./_etcd-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "etcd.client.advertiseUrls"
        "etcd.client.enableGrpcGateway"
        "etcd.client.listenUrls"
        "etcd.client.tls.certificate"
        "etcd.client.tls.clientCertificateAuth"
        "etcd.client.tls.enable"
        "etcd.client.tls.privateKey"
        "etcd.client.tls.trustedCa"
        "etcd.cluster.members"
        "etcd.cluster.state"
        "etcd.cluster.token"
        "etcd.enable"
        "etcd.metrics"
        "etcd.name"
        "etcd.peer.advertiseUrls"
        "etcd.peer.listenUrls"
        "etcd.peer.tls.certificate"
        "etcd.peer.tls.clientCertificateAuth"
        "etcd.peer.tls.enable"
        "etcd.peer.tls.privateKey"
        "etcd.peer.tls.trustedCa"
        "etcd.storage.autoCompaction.mode"
        "etcd.storage.autoCompaction.retention"
        "etcd.storage.quotaBackendBytes"
        "etcd.storage.snapshotCount"
      ];
      ownsRoots = [
        {
          root = "etcd";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = ["aos/packages/etcd/etcd.json"];
        units = [];
        users = [];
        groups = [];
      };
    };

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
          ln -s ${control}/bin/etcd-control $out/bin/etcd-control
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
            ({lib, ...}: {
              options = {
                assertions = lib.mkOption {
                  type = lib.types.listOf lib.types.attrs;
                  default = [];
                };
                etcd.config = lib.mkOption {
                  type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                  default = {};
                };
                etcd.credentials = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
                environment.etc = lib.mkOption {
                  type = lib.types.attrsOf lib.types.anything;
                  default = {};
                };
              };
            })
            (import ./_etcd-config/module.nix)
            {etcd = etcdConfig;}
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
      renderedConfig = builtins.toFile "etcd-config-module-check.json" evaluated.config.environment.etc."aos/packages/etcd/etcd.json".text;
      signedExpose = builtins.fromJSON self.expose.manifest;
      signedCredentials = signedExpose.expose.config.credentials;
      credentialContract =
        builtins.length signedCredentials
        == builtins.length credentialNames
        && builtins.all (credential:
          builtins.elem credential.name credentialNames
          && credential.source == "/run/credstore/etcd/${credential.name}"
          && !credential.encrypted
          && credential.optional
          && credential.units == ["etcd.service"])
        signedCredentials;
      contractHolds =
        assertionsHold evaluated
        && !assertionsHold invalidMember
        && !assertionsHold invalidTls
        && !assertionsHold invalidDuplicate
        && credentialContract;
    in {
      version = testing.mkToolCheck {
        pname = "tool-etcd";
        tool = self;
        command = "etcd --version";
      };

      config-module = testing.mkVMTest {
        name = "db-etcd-config-module";
        rootfsDeps = [self renderedConfig pkgs.iproute2];
        testScript = ''
          ${pkgs.iproute2}/sbin/ip link set lo up
          mkdir -p /var/lib/aos-pkg-etcd
          etcd --config-file ${renderedConfig} >/tmp/etcd.log 2>&1 &
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
          echo "==> etcd typed config and real-binary lifecycle: PASS"
        '';
      };

      config-module-contract =
        if contractHolds
        then
          pkgs.runCommand "db-etcd-config-module-contract" {} ''
            ${pkgs.grep}/bin/grep -qx 'EnvironmentFile=/etc/aos/packages/etcd/service.env' ${self.expose}/units/etcd.service
            ${pkgs.grep}/bin/grep -Fq -- '--config-file /etc/aos/packages/etcd/etcd.json' ${self.expose}/units/etcd.service
            ${pkgs.grep}/bin/grep -qx 'StateDirectory=aos-pkg-etcd' ${self.expose}/units/etcd.service
            if ${pkgs.grep}/bin/grep -Eq 'LoadCredential(Encrypted)?=.*(client|peer)-(certificate|private-key|trusted-ca)' ${self.expose}/units/etcd.service; then
              echo "optional etcd credentials created unconditional unit bindings" >&2
              exit 1
            fi
            ${pkgs.grep}/bin/grep -Fq '"initial-cluster":"node-a=http://127.0.0.1:12380"' ${renderedConfig}
            ${pkgs.grep}/bin/grep -Fq '"data-dir":"/var/lib/aos-pkg-etcd"' ${renderedConfig}
            mkdir -p "$out"
            printf '%s\n' PASS >"$out/result"
          ''
        else throw "the etcd config-module contract checks failed";
    };

    meta = {
      description = "etcd — distributed reliable key-value store";
      homepage = "https://etcd.io";
      license = "Apache-2.0";
    };
  }
