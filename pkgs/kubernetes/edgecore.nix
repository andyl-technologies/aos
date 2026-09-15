##! EdgeCore — KubeEdge edge-side agent
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  kubeedgeSource,
}:
let
  inherit (kubeedgeSource) version src;
in
mkDerivation {
  pname = "edgecore";
  inherit version;
  inherit src;

  buildDeps = [ buildPackages.go ];
  runtimeDeps = [ ];

  abilities = ./_edgecore-config/module.nix;

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd kubeedge-${version}
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export GOCACHE=$TMPDIR/go-cache
        export CGO_ENABLED=0
        export GOPROXY=off
        if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
          export GOOS="$AOS_GOOS"
          export GOARCH="$AOS_GOARCH"
        fi
        # KubeEdge uses a Go workspace (go.work) but the vendor dir was
        # created from go.mod replace directives. Disable workspace mode
        # so -mod=vendor uses go.mod consistently with vendor/modules.txt.
        export GOWORK=off
        export GOFLAGS="-trimpath -mod=vendor"
        mkdir -p "$GOPATH" "$GOCACHE"

        go build -ldflags "-s -w \
          -X github.com/kubeedge/kubeedge/pkg/version.Version=v${version}" \
          -o edgecore ./edge/cmd/edgecore
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 edgecore $out/bin/
      '';
    }
  ];

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    let
      evaluated = lib.evalModules {
        inherit lib;
        modules = [
          ../../modules/abilities/default.nix
          {
            aos.abilities.environment = {
              authority = "deployment";
              key = "edgecore-package-check";
              stage = "host";
            };
            edgecore = {
              enable = true;
              nodeName = "edge-01";
              cloudHub = {
                httpServer = "https://192.0.2.20:10002";
                server = "192.0.2.20:10000";
              };
              tls = {
                caCertificate.ref = "system-credential:kubeedge-ca";
                clientCertificate.ref = "system-credential:edge-01-cert";
                clientPrivateKey.ref = "system-credential:edge-01-key";
              };
            };
          }
        ];
        packageModules = [
          {
            name = "edgecore";
            inherit version;
            module = ./_edgecore-config/module.nix;
          }
        ];
      };
      configurationSource =
        evaluated.config.aos.abilities.requests."edgecore:configuration".parameters.source;
      renderedLiterals = lib.concatMapStrings (
        fragment: if fragment.kind == "literal" then fragment.text else "<credential-path>"
      ) configurationSource.fragments;
    in
    {
      version = testing.mkToolCheck {
        pname = "tool-edgecore";
        tool = self;
        command = "edgecore --help";
      };

      config = pkgs.runCommand "edgecore-config-module" { } ''
        config=${builtins.toFile "package-config.yaml" renderedLiterals}
        grep -F 'apiVersion: edgecore.config.kubeedge.io/v1alpha2' "$config"
        grep -F '    hostnameOverride: edge-01' "$config"
        grep -F '      server: 192.0.2.20:10000' "$config"
        test '${configurationSource.kind}' = interpolated-text
        test '${
          toString (
            builtins.length (
              builtins.filter (fragment: fragment.kind == "execution-path") configurationSource.fragments
            )
          )
        }' -gt 0
        touch "$out"
      '';
    };

  meta = {
    description = "EdgeCore — KubeEdge edge-side agent";
    homepage = "https://kubeedge.io";
    license = "Apache-2.0";
  };
}
