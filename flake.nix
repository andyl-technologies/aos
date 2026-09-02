{
  description = "ANDYL OS — immutable Linux systems and cross-platform host tooling built from source";

  inputs = {};

  outputs = _: let
    linuxSystems = [
      "x86_64-linux"
      "aarch64-linux"
    ];
    darwinSystems = [
      "x86_64-darwin"
      "aarch64-darwin"
    ];
    systems = linuxSystems ++ darwinSystems;

    genAttrs = names: f:
      builtins.listToAttrs (
        map (n: {
          name = n;
          value = f n;
        })
        names
      );

    flattenAttrPairs = prefix: attrs:
      builtins.concatMap (
        name: let
          value = attrs.${name};
          prefixedName = "${prefix}-${name}";
        in
          if builtins.isAttrs value && !(value ? type && value.type == "derivation")
          then flattenAttrPairs prefixedName value
          else [
            {
              name = prefixedName;
              inherit value;
            }
          ]
      ) (builtins.attrNames attrs);

    flattenAttrs = prefix: attrs:
      builtins.listToAttrs (flattenAttrPairs prefix attrs);

    withMainProgram = program: package:
      package
      // {
        meta =
          (package.meta or {})
          // {
            mainProgram = program;
          };
      };

    isDarwinSystem = system: builtins.elem system darwinSystems;
    aosFor = system:
      if isDarwinSystem system
      then
        import ./. {
          # The source bootstrap is Linux-only. Darwin packages are produced
          # hermetically by the canonical Linux-hosted cross environment and
          # execute natively after they reach the target host.
          system = "x86_64-linux";
          crossSystem = system;
        }
      else import ./. {inherit system;};

    # Flatten systems into flake packages:
    #   server-image-raw, server-image-qcow2, edge-image-raw, etc.
    # Auto-enumerates both system names and image formats.
    systemPackages = aos: let
      sysNames = builtins.attrNames aos.systems;
      forSystem = name: let
        formats = builtins.attrNames aos.systems.${name}.build.image;
        artifacts = aos.systems.${name}.config.system.build.imageArtifacts;
        artifactFormats = builtins.attrNames artifacts;
      in
        builtins.listToAttrs (
          map (fmt: {
            name = "${name}-image-${fmt}";
            value = aos.systems.${name}.build.image.${fmt};
          })
          formats
        )
        // builtins.listToAttrs (
          builtins.concatMap (
            fmt:
              map (kind: {
                name = "${name}-image-${fmt}-${kind}";
                value = artifacts.${fmt}.${kind};
              }) ["disk" "info"]
          )
          artifactFormats
        );
    in
      builtins.foldl' (acc: name: acc // forSystem name) {} sysNames;

    # Expose every individual aos package as `pkg-<name>` so a single
    # component (e.g. `pkg-zlib`, `pkg-gcc`) can be built/benchmarked in
    # isolation rather than only the whole OS. packageNames comes from the
    # structural filesystem discovery pass, so enumerating flake outputs does
    # not force every package or trigger unrelated IFDs.
    pkgPackages = aos: let
      p = aos.pkgs;
    in
      builtins.listToAttrs (map (name: {
          name = "pkg-${name}";
          value = p.${name};
        })
        p.packageNames);
  in {
    aosSystems = genAttrs linuxSystems (system: (aosFor system).systems);

    packages = genAttrs systems (
      system: let
        aos = aosFor system;
        individualPackages = pkgPackages aos;
        allPackages = aos.pkgs.mkDerivation {
          pname = "aos-all-packages";
          version = "0";
          src = null;
          buildDeps = builtins.attrValues individualPackages;
          phases = [
            {
              name = "assemble";
              script = ''
                mkdir -p $out
                echo "PASS" > $out/result
              '';
            }
          ];
        };
      in
        (
          {
            default = withMainProgram "aos" aos.pkgs.aos;
            aos = withMainProgram "aos" aos.pkgs.aos;
            apm = withMainProgram "apm" aos.pkgs.aos.apm;
            apr = withMainProgram "apr" aos.pkgs.aos.apr;
            all = allPackages;
          }
          // (
            if isDarwinSystem system
            then {}
            else {
              crucible-nginx-curl-guest = import ./tests/crucible/_nginx-curl-http-200-guest.nix {
                pkgs = aos.pkgs;
              };
            }
          )
        )
        // (
          if isDarwinSystem system
          then {}
          else systemPackages aos
        )
        // individualPackages
    );

    devShells = genAttrs systems (
      system: {
        default = import ./lib/flake-dev-shell.nix {
          aos = aosFor system;
          inherit system;
        };
      }
    );

    formatter = genAttrs systems (system: (aosFor system).pkgs.alejandra);

    checks = genAttrs linuxSystems (
      system: let
        aos = aosFor system;
      in
        {
          aos = aos.pkgs.aos;

          format = aos.pkgs.mkDerivation {
            pname = "aos-format-check";
            version = "0";
            src = ./.;
            buildDeps = [aos.pkgs.alejandra];
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
          rust-cargo-artifacts = aos.checks.rust.cargo-artifacts;
          rust-aos = aos.checks.rust.aos;
          rust-crucible-controller = aos.checks.rust.crucible-controller;
          rust-crucible-qemu-plugin = aos.checks.rust.crucible-qemu-plugin;
          rust-crucible-guest = aos.checks.rust.crucible-guest;
        }
        // flattenAttrs "build" aos.checks.build
        # Per-system module checks: server-boot-basics, edge-boot-basics, etc.
        // flattenAttrs "server" aos.systems.server.checks
        // flattenAttrs "edge" aos.systems.edge.checks
        # Package integration checks
        // flattenAttrs "integration" aos.checks.integration
        # Fleet tests (multi-VM)
        // flattenAttrs "fleet" aos.checks.fleet
    );
  };
}
