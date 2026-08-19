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

    # Expose every individual aos package as `pkg-<name>` so a single
    # component (e.g. `pkg-zlib`, `pkg-gcc`) can be built/benchmarked in
    # isolation rather than only the whole OS. Filtered to derivations
    # so the non-package helpers in the set (lib, mkDerivation, fetchurl,
    # …) don't leak into the flake outputs and break `nix flake check`.
    pkgPackages = aos: let
      p = aos.pkgs;
      isDrv = name: let
        r = builtins.tryEval p.${name};
      in
        r.success && builtins.isAttrs r.value && (r.value.type or null) == "derivation";
      names = builtins.filter isDrv (builtins.attrNames p);
    in
      builtins.listToAttrs (map (name: {
          name = "pkg-${name}";
          value = p.${name};
        })
        names);
  in {
    aosSystems = genAttrs systems (system: (aosFor system).systems);

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
        {
          default = aos.pkgs.aos;
          aos = aos.pkgs.aos;
          all = allPackages;
          crucible-nginx-curl-guest = import ./tests/crucible/_nginx-curl-http-200-guest.nix {
            pkgs = aos.pkgs;
          };
        }
        // systemPackages aos
        // individualPackages
    );

    devShells = genAttrs systems (
      system: let
        aos = aosFor system;
        packages = [
          (aos.pkgs.aos.overrideAttrs (_: {doCheck = false;}))
          aos.pkgs.just
          aos.pkgs.rust
          aos.pkgs.rust.dev
          aos.pkgs.bootstrapTools
          aos.pkgs.perl
          aos.pkgs.pkg-config
          aos.pkgs.openssl
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
              # OPENSSL_DIR above only lets `openssl-sys` *link* against the AOS
              # OpenSSL; the resulting binary still records only the SONAME, so
              # an impure `cargo build` produces a binary that cannot find
              # libssl at runtime. Bake the OpenSSL dir into the binary's rpath
              # at link time, so `./target/debug/{aos,apr,apm}` run directly —
              # no patchelf, and no LD_LIBRARY_PATH that would poison the `nix`
              # subprocess they shell out to (which needs its own, newer
              # OpenSSL). rpath is per-binary, so each keeps its own OpenSSL.
              export ${cargoHostRustflagsVar}="-C link-arg=-Wl,-rpath,${aos.pkgs.openssl}/lib"
            '';
        };
      }
    );

    formatter = genAttrs systems (system: (aosFor system).pkgs.alejandra);

    checks = genAttrs systems (
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
