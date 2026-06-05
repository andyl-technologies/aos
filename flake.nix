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

    prefixAttrs = prefix: attrs:
      builtins.listToAttrs (
        map (name: {
          name = "${prefix}-${name}";
          value = attrs.${name};
        }) (builtins.attrNames attrs)
      );

    aosFor = system: import ./. {inherit system;};

    # Flatten systems into flake packages:
    #   server-image-raw, server-image-qcow2, edge-image-raw, etc.
    # Auto-enumerates both system names and image formats.
    systemPackages = aos: let
      sysNames = builtins.attrNames aos.systems;
      forSystem = name: let
        formats = builtins.attrNames aos.systems.${name}.build.image;
      in
        builtins.listToAttrs (
          map (fmt: {
            name = "${name}-image-${fmt}";
            value = aos.systems.${name}.build.image.${fmt};
          })
          formats
        );
    in
      builtins.foldl' (acc: name: acc // forSystem name) {} sysNames;

    # The single, flat source of truth for CI. Every attribute is a leaf
    # derivation (no nested attrsets) so it works uniformly with
    # `nix flake check`, `nix build .#checks.<system>.<name>`, and the
    # GitHub Actions matrix generator. The naming convention is what the
    # matrix classifier keys off (see lib/ci/github-matrix.nix):
    #   format/lint/eval/cargo-fmt/cargo-clippy/tla-*  → fast        (tier 0)
    #   cargo-test/cargo-doc/aos/build-*               → build       (tier 1)
    #   server-/edge-/integration-/fleet-/vm-          → virtualized (tier 2, KVM)
    checksFor = system: let
      aos = aosFor system;
    in
      {
        # --- Fast lane: style, lint, pure eval (tier 0) ---
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
        lint = aos.checks.lint;
        eval = aos.checks.eval;

        # The `aos` CLI binary build (tier 1).
        aos = aos.pkgs.aos;

        # --- Build checks (tier 1) ---
        build-critical-pkgs = aos.checks.build.critical-pkgs;
        build-kernel-config = aos.checks.build.kernel-config;
        # Aggregate the compiler-hardening probes into one job (each probe
        # is a tiny compile, not worth its own status). Mirrors the
        # aggregation in aos.checks.build.all.
        build-hardening = aos.pkgs.mkDerivation {
          pname = "aos-build-hardening";
          version = "0";
          src = null;
          buildDeps = builtins.attrValues aos.checks.build.hardening-probe;
          phases = [
            {
              name = "check";
              script = ''
                mkdir -p $out
                echo "PASS" > $out/result
              '';
            }
          ];
        };
      }
      # --- Rust workspace gates: cargo-fmt, cargo-clippy, cargo-test, cargo-doc ---
      // aos.checks.rust
      # --- TLA+ model checks: tla-statute, tla-jobs, … (tier 0) ---
      // prefixAttrs "tla" aos.checks.tla
      # --- Remaining pure-eval library checks (tier 0) ---
      // {
        inherit
          (aos.checks)
          module-args
          module-enforcement
          ignition-format
          fleet-spec
          systemd-lib
          systemd-generate
          trivial-builders
          ;
      }
      # --- Per-system module VM checks: server-*, edge-* (tier 2, KVM) ---
      // prefixAttrs "server" aos.systems.server.checks
      // prefixAttrs "edge" aos.systems.edge.checks
      # --- Package integration checks, Firecracker (tier 2, KVM) ---
      // prefixAttrs "integration" aos.checks.integration
      # --- Fleet tests, multi-VM (tier 2, KVM) ---
      // prefixAttrs "fleet" aos.checks.fleet;
  in {
    aosSystems = genAttrs systems (system: (aosFor system).systems);

    packages = genAttrs systems (
      system: let
        aos = aosFor system;
      in
        {
          default = aos.pkgs.aos;
          aos = aos.pkgs.aos;
        }
        // systemPackages aos
    );

    devShells = genAttrs systems (
      system: let
        aos = aosFor system;
        packages = [
          aos.pkgs.aos
          aos.pkgs.just
          aos.pkgs.rust
          aos.pkgs.rust.dev
          aos.pkgs.bootstrapTools
          aos.pkgs.perl
          aos.pkgs.pkg-config
          aos.pkgs.openssl
          aos.pkgs.protobuf
        ];
        binPath = builtins.concatStringsSep ":" (map (p: "${p}/bin") packages);
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
              export AOS_ROOT="$(pwd)"
              export RUST_SRC_PATH="${aos.pkgs.rust.dev}/lib/rustlib/src/rust/library"
              export OPENSSL_DIR="${aos.pkgs.openssl}"
              export OPENSSL_LIB_DIR="${aos.pkgs.openssl}/lib"
              export OPENSSL_INCLUDE_DIR="${aos.pkgs.openssl}/include"
              export OPENSSL_NO_VENDOR=1
              export OPENSSL_STATIC=0
              export PROTOC="${aos.pkgs.protobuf}/bin/protoc"
            '';
        };
      }
    );

    formatter = genAttrs systems (system: (aosFor system).pkgs.alejandra);

    checks = genAttrs systems checksFor;

    # CI job groups: a small, fixed set of functional aggregates (lint,
    # rust, eval, tla, build, integration, vm, fleet). Each builds its
    # whole group with one `nix build`, so shared closures are realised
    # once. Consumed by .github/workflows/ci.yml:
    #   nix build .#ciGroups.x86_64-linux.<group>
    # Checks stay individually addressable under `checks.<system>.<name>`;
    # `ciGroups` is just how the workflow segments them into jobs.
    ciGroups = genAttrs systems (
      system: let
        aos = aosFor system;
        groups = import ./lib/ci/groups.nix {inherit (aos) lib pkgs;};
      in
        groups.mkCiGroups (checksFor system)
    );
  };
}
