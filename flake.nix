{
  description = "ANDYL OS — immutable, minimal Linux distribution built from source";

  inputs = {};

  outputs = _: let
    systems = [
      "x86_64-linux"
      "aarch64-linux"
    ];

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

    aosFor = system: import ./. {inherit system;};

    coordinatedContainer = variant: _: let
      # The bootstrap ladder starts on x86_64 and performs its reviewed
      # x86_64→aarch64 transition at gcc4_8_cross. Post-cross target tools run
      # through the build host's configured QEMU binfmt handler while Nix keeps
      # scheduling the derivations on x86_64.
      coordinatorSystem = "x86_64-linux";
      coordinator = aosFor coordinatorSystem;
      platformBuilds = [
        coordinator.systems.${variant}.build.defaultContainer
        (import ./. {
          system = coordinatorSystem;
          crossSystem = "aarch64-linux";
        })
        .systems
        .${
          variant
        }
        .build
        .defaultContainer
      ];
      oci = import ./lib/build/oci {
        inherit (coordinator) lib;
        inherit (coordinator.pkgs) mkDerivation coreutils findutils gzip jq tar;
      };
    in
      import ./lib/containers/multi-platform.nix {
        inherit (coordinator) lib pkgs;
        inherit oci platformBuilds;
        name = "aos";
      };

    productionContainer = coordinatedContainer "server";
    testingContainer = coordinatedContainer "aos-testing";

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

    containerPackages = system: aos: production:
      builtins.listToAttrs (
        builtins.concatMap (
          name: let
            container = aos.containerImages.${name};
            platform = container.platforms.${system};
          in [
            {
              name = "container-${name}-oci";
              value = platform.ociLayout;
            }
            {
              name = "container-${name}-docker";
              value = platform.dockerArchive;
            }
            {
              name = "container-${name}-metadata";
              value = platform.metadata;
            }
            {
              name = "container-${name}-index";
              value = production.ociIndex;
            }
            {
              name = "container-${name}-platform-index";
              value = container.ociIndex;
            }
            {
              name = "container-${name}-evidence";
              value = production.evidence;
            }
            {
              name = "container-${name}-publication-inputs";
              value = production.publicationInputs;
            }
            {
              name = "container-${name}-qualification";
              value = production.check;
            }
          ]
        ) (builtins.attrNames aos.containerImages)
      );

    testingContainerPackages = system: aos: coordinated: let
      container = aos.systems.aos-testing.build.defaultContainer;
      platform = container.platforms.${system};
    in {
      container-aos-testing-oci = platform.ociLayout;
      container-aos-testing-docker = platform.dockerArchive;
      container-aos-testing-metadata = platform.metadata;
      container-aos-testing-index = coordinated.ociIndex;
      container-aos-testing-platform-index = container.ociIndex;
      container-aos-testing-evidence = coordinated.evidence;
      container-aos-testing-publication-inputs = coordinated.publicationInputs;
      container-aos-testing-qualification = coordinated.check;
    };
  in {
    aosSystems = genAttrs systems (system: (aosFor system).systems);

    packages = genAttrs systems (
      system: let
        aos = aosFor system;
        production = productionContainer system;
        testing = testingContainer system;
        individualPackages = pkgPackages aos;
        containers =
          containerPackages system aos production
          // testingContainerPackages system aos testing;
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
        {
          default = aos.pkgs.aos;
          aos = aos.pkgs.aos;
          apm = aos.pkgs.aos.apm;
          apr = aos.pkgs.aos.apr;
          all = allPackages;
          crucible-nginx-curl-guest = import ./tests/crucible/_nginx-curl-http-200-guest.nix {
            pkgs = aos.pkgs;
          };
        }
        // systemPackages aos
        // containers
        // individualPackages
    );

    devShells = genAttrs systems (
      system: let
        aos = aosFor system;
        aosCli = aos.pkgs.aos.overrideAttrs (_: {doCheck = false;});
        packages = [
          aosCli
          aosCli.apm
          aosCli.apr
          aos.pkgs.just
          aos.pkgs.rust
          aos.pkgs.rust.dev
          aos.pkgs.cargo-nextest
          aos.pkgs.cargo-hakari
          aos.pkgs.bootstrapTools
          aos.pkgs.perl
          aos.pkgs.pkg-config
          aos.pkgs.aos-fuse-transport
          aos.pkgs.openssl
          aos.pkgs.sqlite
          aos.pkgs.protobuf
          # Runtime tools the aos/apm/apr binaries shell out to by bare name
          # (see runtimeTools in pkgs/tools/aos/aos.nix), so impure cargo runs
          # in the dev shell resolve the same AOS-built tools the hermetic build
          # uses instead of falling back to whatever is installed on the host.
          aos.pkgs.git
          aos.pkgs.gnupg
          aos.pkgs.openssh
          aos.pkgs.sbsigntools
          aos.pkgs.systemd
          aos.pkgs.tar
          aos.pkgs.zstd
          aos.pkgs.which
        ];
        binPath = builtins.concatStringsSep ":" (map (p: "${p}/bin") packages);
        # Per-target cargo rustflags env var for the dev-shell host. Used to
        # inject an OpenSSL rpath for native `cargo build` (see shellHook)
        # without disturbing the wasm32 rustflags in crates/.cargo/config.toml:
        # a plain RUSTFLAGS would replace those and break the Workers build.
        cargoHostRustflagsVar = builtins.getAttr system {
          "x86_64-linux" = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS";
          "aarch64-linux" = "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS";
        };
      in {
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
              if binPath != ""
              then ''
                export PATH="${binPath}''${PATH:+:$PATH}"
              ''
              else ""
            )
            + ''
              export RUST_SRC_PATH="${aos.pkgs.rust.dev}/lib/rustlib/src/rust/library"
              export OPENSSL_DIR="${aos.pkgs.openssl}"
              export OPENSSL_NO_VENDOR=1
              export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
              export PKG_CONFIG_PATH="${aos.pkgs.aos-fuse-transport}/lib/pkgconfig:${aos.pkgs.sqlite}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
              # OPENSSL_DIR above only lets `openssl-sys` *link* against the AOS
              # OpenSSL and pkg-config above only let native crates link against
              # the AOS libraries; the resulting binary still records SONAMEs.
              # Bake all three library directories into native cargo binaries so
              # they run directly without an LD_LIBRARY_PATH that would poison
              # the `nix` subprocesses they launch.
              export ${cargoHostRustflagsVar}="-C link-arg=-Wl,-rpath,${aos.pkgs.openssl}/lib -C link-arg=-Wl,-rpath,${aos.pkgs.sqlite}/lib -C link-arg=-Wl,-rpath,${aos.pkgs.aos-fuse-transport}/lib"
            '';
        };
      }
    );

    formatter = genAttrs systems (system: (aosFor system).pkgs.alejandra);

    checks = genAttrs systems (
      system: let
        production = productionContainer system;
        aos = import ./. {
          inherit system;
          containerPublicationInputsOverride = production.publicationInputs;
        };
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
        // flattenAttrs "container" aos.checks.container
        // flattenAttrs "qualification" (builtins.removeAttrs aos.checks.qualification ["inventory"])
        // {
          container-multi-platform = production.check;
        }
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
