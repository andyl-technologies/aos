# A downstream repository that uses only the documented AOS flake API:
# builders from `aos.lib.<system>` and the package attributes listed in
# docs/engineering/downstream/flake-api.md. AOS's checks call `outputs`
# directly with the checkout's own exports. To run it as a flake:
#
#   nix flake check --override-input aos path:<aos checkout> path:.
{
  description = "Downstream fixture for the AOS flake API";

  inputs.aos.url = "github:andyl-technologies/aos";

  nixConfig = {
    extra-substituters = ["https://cdn.aos.andyl.org/andyl/experimental/"];
    extra-trusted-public-keys = [
      "andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I="
    ];
    fallback = true;
  };

  outputs = {
    self,
    aos,
  }: let
    systems = builtins.attrNames aos.lib;

    forAllSystems = f:
      builtins.listToAttrs (map (system: {
          name = system;
          value = f system;
        })
        systems);

    ociArchitecture = system:
      {
        x86_64-linux = "amd64";
        aarch64-linux = "arm64";
      }
      .${
        system
      };
  in {
    packages = forAllSystems (system: let
      aosLib = aos.lib.${system};
      aosPkgs = aos.legacyPackages.${system};
    in rec {
      c-hello = aosLib.callPackage ./c/package.nix {
        inherit (aosLib) replacePhase addPhaseAfter removePhase;
      };

      rust-hello = aosLib.mkCargoPackage {
        pname = "rust-hello";
        version = "1.0.0";
        src = ./rust;
        cargoDeps = aosLib.fetchCargoVendor {
          src = ./rust;
          hash = "sha256-vUH7V/YGMGC+3F8PnlVxsHih6NbuchwbmUzgMqYWeuY=";
        };
      };

      go-hello = aosLib.mkGoPackage {
        pname = "go-hello";
        version = "1.0.0";
        src = ./go;
      };

      greeting = aosLib.writeTextFile {
        name = "greeting";
        text = "text: hello\n";
        destination = "/share/greeting.txt";
      };

      # Store references in the script text are kept, so the script runs
      # with AOS coreutils instead of whatever the host provides.
      hello-all = aosLib.writeShellScriptBin "hello-all" ''
        ${c-hello}/bin/c-hello
        ${rust-hello}/bin/rust-hello
        ${go-hello}/bin/go-hello
        ${aosPkgs.coreutils}/bin/cat ${greeting}/share/greeting.txt
      '';

      oci-image = let
        platform = {
          os = "linux";
          architecture = ociArchitecture system;
        };
        payload = aosLib.ociTools.mkClosureLayer {
          roots = [hello-all];
          pname = "fixture-payload";
        };
        metadata = aosLib.ociTools.mkMetadataLayer {
          storeLayers = [payload];
          directories = map (path: {inherit path;}) ["/tmp" "/work"];
          pname = "fixture-metadata";
        };
      in
        aosLib.ociTools.mkImageLayout {
          pname = "fixture-image";
          layers = [payload metadata];
          runtimeAudit = aosLib.ociTools.mkRuntimeClosureAudit {
            name = "fixture";
            roots = [hello-all];
            maxClosureMiB = 256;
            maxDevelopmentPayloadMiB = 4;
          };
          deploymentArtifact = aosLib.ociTools.mkDeploymentArtifact {
            pname = "fixture-deployment";
            inherit platform;
            scope = ["container" "fixture"];
            packages = [hello-all];
          };
          referenceName = "example.invalid/fixture:1";
          config.entrypoint = ["${hello-all}/bin/hello-all"];
        };

      default = hello-all;
    });

    devShells = forAllSystems (system: let
      aosPkgs = aos.legacyPackages.${system};
    in {
      default = aos.lib.${system}.mkShell {
        name = "fixture-dev";
        buildDeps = [
          aosPkgs.rust
          aosPkgs.go
          aosPkgs.gnumake
        ];
      };
    });

    checks = forAllSystems (system: let
      aosLib = aos.lib.${system};
      packages = self.packages.${system};
      expected = aosLib.writeTextFile {
        name = "hello-all-expected";
        text = ''
          c: hello
          rust: hello
          go: hello
          text: hello
        '';
      };
    in {
      hello-all = aosLib.runCommand "hello-all-check" {} ''
        ${packages.hello-all}/bin/hello-all > actual
        cmp actual ${expected}
      '';

      oci-image = aosLib.runCommand "oci-image-check" {} ''
        test -s ${packages.oci-image}/image.oci.tar
        grep -q '/bin/hello-all' ${packages.oci-image}/config.json
      '';
    });
  };
}
