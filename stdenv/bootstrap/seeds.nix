# stdenv/bootstrap/seeds.nix — Bootstrap seeds (hex0 + kaem)
#
# Fixed-output derivation containing the minimal binary seeds (~357 bytes)
# that form the root of trust for the entire bootstrap chain.
#
# hex0: reads hex pairs from stdin, writes raw bytes to stdout.
#        This is the simplest possible "compiler" — hand-auditable x86 assembly.
#
# kaem: minimal script executor. Reads a file line-by-line and executes
#        each line as a command. No variables, no control flow.
#
# Together these ~357 bytes are the ONLY pre-compiled binaries in the
# entire AOS build chain. Everything else is built from source.
#
# Source: https://github.com/oriansj/bootstrap-seeds
#
{
  system ? "x86_64-linux",
  storeDir ? "/nix/store",
}: let
  # Version of the bootstrap-seeds repository
  version = "1.0.0";

  # The seeds archive from GitHub
  seedsArchive = builtins.derivation {
    name = "bootstrap-seeds-source-${version}";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://github.com/oriansj/bootstrap-seeds/archive/refs/tags/${version}.tar.gz";

    # Fixed-output derivation: content is verified by hash
    outputHash = "0000000000000000000000000000000000000000000000000000"; # TODO: compute real sha256 hash
    outputHashMode = "flat";
    outputHashAlgo = "sha256";

    preferLocalBuild = true;
  };

  # Extract the architecture-specific seeds
  seeds = builtins.derivation {
    name = "aos-bootstrap-seeds-${version}";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu

        mkdir -p $out/bin

        # Extract the archive
        tar xzf ${seedsArchive}
        cd bootstrap-seeds-${version}

        # Select architecture-specific seeds
        arch_dir=""
        case "${system}" in
          x86_64-linux)
            arch_dir="NATIVE/x86"
            ;;
          aarch64-linux)
            arch_dir="NATIVE/AArch64"
            ;;
          *)
            echo "Unsupported architecture: ${system}"
            exit 1
            ;;
        esac

        # Install hex0 seed binary
        # hex0 is a ~357 byte x86 binary that reads hex pairs and writes bytes.
        # It is small enough to audit by hand (or verify against the assembly listing).
        if [ -f "$arch_dir/hex0-seed" ]; then
          install -m 755 "$arch_dir/hex0-seed" $out/bin/hex0
        else
          echo "hex0 seed not found at $arch_dir/hex0-seed"
          exit 1
        fi

        # Install kaem seed binary (minimal script runner)
        if [ -f "$arch_dir/kaem-optional-seed" ]; then
          install -m 755 "$arch_dir/kaem-optional-seed" $out/bin/kaem
        fi

        # Install the hex0 source (assembly) for auditability
        mkdir -p $out/src
        if [ -f "$arch_dir/hex0_x86.hex0" ]; then
          cp "$arch_dir/hex0_x86.hex0" $out/src/
        fi

        # Record metadata
        cat > $out/manifest.json << EOF
        {
          "name": "aos-bootstrap-seeds",
          "version": "${version}",
          "architecture": "${system}",
          "description": "Minimal binary seeds for full-source bootstrap",
          "seed_sizes": {
            "hex0": "$(wc -c < $out/bin/hex0) bytes",
            "kaem": "$(wc -c < $out/bin/kaem 2>/dev/null || echo 'not installed') bytes"
          },
          "source": "https://github.com/oriansj/bootstrap-seeds"
        }
        EOF
      ''
    ];
  };
in
  seeds
  // {
    inherit version;
    meta = {
      description = "Minimal binary seeds (hex0 + kaem) for full-source bootstrap";
      homepage = "https://github.com/oriansj/bootstrap-seeds";
      license = "GPL-3.0-or-later";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    };
  }
