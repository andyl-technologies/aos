{
  description = "ANDYL OS — immutable, minimal Linux distribution built from source";

  inputs = { };

  outputs =
    _:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      genAttrs =
        names: f:
        builtins.listToAttrs (
          map (n: {
            name = n;
            value = f n;
          }) names
        );

      prefixAttrs =
        prefix: attrs:
        builtins.listToAttrs (
          map (name: {
            name = "${prefix}-${name}";
            value = attrs.${name};
          }) (builtins.attrNames attrs)
        );

      aosFor = system: import ./. { inherit system; };

      # Flatten systems into flake packages:
      #   server-image-raw, server-image-qcow2, edge-image-raw, etc.
      # Auto-enumerates both system names and image formats.
      systemPackages =
        aos:
        let
          sysNames = builtins.attrNames aos.systems;
          forSystem =
            name:
            let
              formats = builtins.attrNames aos.systems.${name}.build.image;
            in
            builtins.listToAttrs (
              map (fmt: {
                name = "${name}-image-${fmt}";
                value = aos.systems.${name}.build.image.${fmt};
              }) formats
            );
        in
        builtins.foldl' (acc: name: acc // forSystem name) { } sysNames;
    in
    {
      aosSystems = genAttrs systems (system: (aosFor system).systems);

      packages = genAttrs systems (
        system:
        let
          aos = aosFor system;
        in
        {
          default = aos.pkgs.aos;
          aos = aos.pkgs.aos;
        }
        // systemPackages aos
      );

      devShells = genAttrs systems (
        system:
        let
          aos = aosFor system;
          packages = [
            aos.pkgs.aos
            aos.pkgs.just
          ];
          binPath = builtins.concatStringsSep ":" (map (p: "${p}/bin") packages);
        in
        {
          default = builtins.derivation {
            name = "aos-dev";
            inherit system;
            outputs = ["out"];
            builder = "${aos.pkgs.bash}/bin/bash";
            args = [
              "-c"
              "echo 'Use nix develop, not nix build' >&2; ${aos.pkgs.coreutils}/bin/mkdir -p $out"
            ];
            shellHook =
              (
                if binPath != "" then
                  ''
                    export PATH="${binPath}''${PATH:+:$PATH}"
                  ''
                else
                  ""
              )
              + ''
                export AOS_ROOT="$(pwd)"
              '';
          };
        }
      );

      formatter = genAttrs systems (system: (aosFor system).pkgs.alejandra);

      checks = genAttrs systems (
        system:
        let
          aos = aosFor system;
        in
        {
          aos = aos.pkgs.aos;

          format = aos.pkgs.mkDerivation {
            pname = "aos-format-check";
            version = "0";
            src = ./.;
            buildDeps = [ aos.pkgs.alejandra ];
            phases = [
              {
                name = "check";
                script = ''
                  alejandra --check $src
                  mkdir -p $out
                  echo "Format check passed" > $out/result
                '';
              }
            ];
          };

          eval = aos.checks.eval;
          build = aos.checks.build;
        }
        # Per-system module checks: server-boot-basics, edge-boot-basics, etc.
        // prefixAttrs "server" aos.systems.server.checks
        // prefixAttrs "edge" aos.systems.edge.checks
        # Package integration checks
        // prefixAttrs "integration" aos.checks.integration
        # Fleet tests (multi-VM)
        // prefixAttrs "fleet" aos.checks.fleet
      );
    };
}
