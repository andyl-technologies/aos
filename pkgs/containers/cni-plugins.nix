##! CNI Plugins — Container Networking Interface reference plugins
{
  lib,
  mkDerivation,
  fetchurl,
  fetchGoModules,
  buildPackages,
  gnumake,
}: let
  version = "1.9.1";
  flannelVersion = "1.9.0-flannel1";
  flannelSrc = fetchurl {
    urls = [
      "https://github.com/flannel-io/cni-plugin/archive/v${flannelVersion}/cni-plugin-${flannelVersion}.tar.gz"
    ];
    hash = "sha256-ie1V2EBX3o3DN+y/D9nQjAzZNJAl52zb6sPCbqkxQI0=";
  };
  flannelGoModules = fetchGoModules {
    src = flannelSrc;
    hash = "sha256-d+j+m9yj9BpMuPS01DBsrhSPoBnifcS262u6fp4/ffI=";
  };
in
  mkDerivation {
    pname = "cni-plugins";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The plugin returns a supportedVersions array containing CNI 1.0.0.";
        "files" = {};
        "input" = "A CNI VERSION request containing the current configuration version.";
        "operation" = "Send the request to the packaged loopback plugin and parse its response.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, subprocess\nenvironment = os.environ.copy()\nenvironment[\"CNI_COMMAND\"] = \"VERSION\"\nresult = subprocess.run(\n    [\"@out@/bin/loopback\"],\n    env=environment,\n    input=b'{\"cniVersion\":\"1.0.0\"}',\n    capture_output=True,\n)\nassert result.returncode == 0\nresponse = json.loads(result.stdout)\nassert \"1.0.0\" in response[\"supportedVersions\"]\nprint(\"cni-plugins operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cni-plugins operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The plugin rejects the request and returns a structured CNI error.";
        "files" = {};
        "input" = "An ADD request with all runtime coordinates but no CNI configuration version.";
        "operation" = "Send the malformed request to the loopback plugin.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, subprocess, sys\nenvironment = os.environ.copy()\nenvironment.update({\n    \"CNI_COMMAND\": \"ADD\",\n    \"CNI_CONTAINERID\": \"qualification\",\n    \"CNI_NETNS\": \"/nonexistent\",\n    \"CNI_IFNAME\": \"lo\",\n    \"CNI_PATH\": \"@out@/bin\",\n})\nresult = subprocess.run([\"@out@/bin/loopback\"], env=environment, input=b'{}', capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nresponse = json.loads(result.stdout)\nassert response[\"code\"] != 0 and response[\"msg\"]\nsys.stderr.write(\"cni-plugins rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "cni-plugins rejected invalid input\n";
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
        "https://github.com/containernetworking/plugins/archive/v${version}/cni-plugins-${version}.tar.gz"
      ];
      hash = "sha256-NL2C1H6YGUB1FhnJzETAlbuQv8r41xhly7giw3aQp2Q=";
    };

    buildDeps = [
      gnumake
      buildPackages.go
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          tar xf ${flannelSrc}
          cd plugins-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOFLAGS="-trimpath -mod=vendor"
          export GOPROXY=off
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          GO_LDFLAGS="-s -w -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v${version}"
          mkdir -p "$GOCACHE"

          mkdir -p bin
          for plugin in bandwidth bridge dhcp dummy firewall host-device host-local \
                        ipvlan loopback macvlan portmap ptp sbr static tap tuning \
                        vlan vrf; do
            echo "Building $plugin..."
            # Find the plugin directory and build it
            plugindir=$(find ./plugins -type d -name "$plugin" | head -1)
            if [ -n "$plugindir" ]; then
              go build -o bin/$plugin -ldflags "$GO_LDFLAGS" "$plugindir"
            else
              echo "WARNING: plugin $plugin not found, skipping"
            fi
          done

          echo "Building flannel..."
          (
            cd ../cni-plugin-${flannelVersion}
            GOPATH="${flannelGoModules}" \
              GOFLAGS="-trimpath -mod=readonly" \
              go build \
                -tags "netgo osusergo no_stage static_build" \
                -ldflags "-s -w \
                  -X main.Program=flannel \
                  -X main.Version=v${flannelVersion} \
                  -X main.Commit=v${flannelVersion}" \
                -o ../plugins-${version}/bin/flannel .
          )
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 bin/* $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      binaries = testing.mkVMTest {
        name = "tool-cni-plugins";
        rootfsDeps = [self];
        testScript = ''
          echo "==> Verifying CNI plugin binaries exist"
          test -x ${self}/bin/bridge
          test -x ${self}/bin/loopback
          test -x ${self}/bin/host-local
          test -x ${self}/bin/portmap
          test -x ${self}/bin/flannel
          echo "==> CNI plugin binaries verified"
        '';
      };
    };

    meta = {
      description = "CNI Plugins — Container Networking Interface reference plugins";
      homepage = "https://github.com/containernetworking/plugins";
      license = "Apache-2.0";
    };
  }
