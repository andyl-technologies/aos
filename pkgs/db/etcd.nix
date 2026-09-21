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

    abilities = ./_etcd-config;

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
      mkSystem,
    }: let
      serviceManagement = lib.abilities.interfaces.serviceManagement;
      environmentId = lib.abilities.environmentId {
        authority = "system-image";
        key = "etcd-package-check";
        stage = "host";
      };
      credentialProvider = lib.abilities.instanceId {
        environment = environmentId;
        key = "credential-provider";
      };
      credential = name:
        lib.abilities.resourceReference {
          interface = serviceManagement.interfaces.credentialDelivery.identity;
          resource = {
            provider = credentialProvider;
            key = name;
          };
          operations = ["observe"];
          lifetime = "persistent";
        };
      tls = prefix: {
        enable = true;
        certificate.resource = credential "${prefix}-certificate";
        privateKey.resource = credential "${prefix}-private-key";
        trustedCa.resource = credential "${prefix}-trusted-ca";
      };
      evalConfig = etcdConfig:
        mkSystem {
          systemName = "etcd-package-check";
          modules = [
            {
              environment.systemPackages = [self];
              etcd = etcdConfig;
            }
          ];
        };
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      ownedValues = lib.filterAttrs (_: value: value.package == self.pname);
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
      evaluateTls = clientTls: peerTls: let
        clientScheme =
          if clientTls
          then "https"
          else "http";
        peerScheme =
          if peerTls
          then "https"
          else "http";
      in
        evalConfig {
          enable = true;
          name = "node-a";
          client = {
            listenUrls = ["${clientScheme}://127.0.0.1:12379"];
            advertiseUrls = ["${clientScheme}://127.0.0.1:12379"];
            tls =
              if clientTls
              then tls "client"
              else {};
          };
          peer = {
            listenUrls = ["${peerScheme}://127.0.0.1:12380"];
            advertiseUrls = ["${peerScheme}://127.0.0.1:12380"];
            tls =
              if peerTls
              then tls "peer"
              else {};
          };
          cluster.members.node-a.peerUrls = ["${peerScheme}://127.0.0.1:12380"];
        };
      tlsEvaluations = {
        neither = evaluateTls false false;
        client = evaluateTls true false;
        peer = evaluateTls false true;
        both = evaluateTls true true;
      };
      credentialRequests = evaluation:
        builtins.map
        (request: request.localKey)
        (builtins.filter
          (request:
            request.package
            == self.pname
            && lib.hasPrefix "credential-" request.localKey)
          (builtins.attrValues evaluation.config.aos.abilities.requests));
      expectedRequestOutput = localKey: output: {
        package = self.pname;
        inherit localKey output;
      };
      disabled = evalConfig {};
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
      enabledAbilityConfig = evaluated.config.aos.abilities;
      disabledAbilityConfig = disabled.config.aos.abilities;
      requests = builtins.attrNames enabledAbilityConfig.requests;
      mainStorageMounts = enabledAbilityConfig.requests."etcd:main-storage".parameters.mounts;
      disabledRequirements = builtins.attrNames disabledAbilityConfig.requirementTemplates;
      configurationSource = enabledAbilityConfig.requests."etcd:server-configuration".parameters.source;
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
        && lib.abilities.types.isPortableOptionTree evaluated.options.etcd
        && !assertionsHold invalidMember
        && !assertionsHold invalidTls
        && !assertionsHold invalidDuplicate
        && ownedValues disabledAbilityConfig.instances == {}
        && ownedValues disabledAbilityConfig.requests == {}
        && builtins.elem "etcd:credential-delivery" disabledRequirements
        && builtins.elem "etcd:main-service-lifecycle" disabledRequirements
        && builtins.elem "etcd:main-lifecycle" requests
        && builtins.elem "etcd:main-dependencies" requests
        && builtins.elem "etcd:main-readiness" requests
        && builtins.elem "etcd:server-configuration" requests
        && builtins.all assertionsHold (builtins.attrValues tlsEvaluations)
        && credentialRequests tlsEvaluations.neither == []
        && credentialRequests tlsEvaluations.client
        == [
          "credential-client-certificate"
          "credential-client-private-key"
          "credential-client-trusted-ca"
        ]
        && credentialRequests tlsEvaluations.peer
        == [
          "credential-peer-certificate"
          "credential-peer-private-key"
          "credential-peer-trusted-ca"
        ]
        && credentialRequests tlsEvaluations.both
        == credentialRequests tlsEvaluations.client ++ credentialRequests tlsEvaluations.peer
        && builtins.map
        (mount:
          lib.abilities.requestOutputIdentity {
            requests = enabledAbilityConfig.requests;
            reference = mount.source;
          })
        mainStorageMounts
        == [
          (expectedRequestOutput "data-storage" "planned-path")
          (expectedRequestOutput "runtime-storage" "planned-path")
        ]
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
