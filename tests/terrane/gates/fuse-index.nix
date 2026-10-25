# Owns the complete structural-index path, including real native custody.
{
  pkgs,
  lib,
  sourceGateWithInputs,
  initialEnrollmentProof,
  ...
}: let
  structural = import ../structural-index.nix {inherit pkgs sourceGateWithInputs;};
  mapping = (import ../structural-mapping.nix {inherit pkgs lib sourceGateWithInputs;}).native;
  owner = import ../host-cache-proof.nix {
    inherit pkgs lib sourceGateWithInputs;
    surfaceIndex = true;
  };
  scoped = options:
    import ../scoped-worker.nix ({
        inherit pkgs lib;
        image = owner.image;
      }
      // options);

  # These are executable prerequisites, not registry membership or source scans.
  # Each guest retains its existing actor deadlines and private disk filesystem.
  prerequisites = {
    codec = structural;
    manifest-open = initialEnrollmentProof.manifestOpen;
    sealed-mapping = mapping;
    physical-owner = owner.native;
    scoped-disclosure = scoped {};
    exposure-pressure = scoped {pressure = true;};
    admission-pressure = scoped {admission = true;};
  };
in {
  fuse-index-roundtrip = pkgs.mkDerivation {
    pname = "terrane-gate-fuse-index-roundtrip";
    version = "0.1.0";
    src = null;
    buildDeps = builtins.attrValues prerequisites;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          mkdir -p "$out"
          ${lib.concatMapStringsSep "\n" (name: let
            check = prerequisites.${name};
          in ''
            test "$(cat ${check}/result)" = PASS
            ln -s ${check} "$out/${name}"
          '') (builtins.attrNames prerequisites)}
          cat > "$out/scope" <<'EOF'
          FUSE-7 through FUSE-12: canonical metadata-only compilation, checked
          sorted lookup and direct-child iteration, original sealed read-only
          mappings, separate native index capacity and exposure pin custody,
          typed content references and recursively expanded graft metadata.
          Actual Serve file open resolves the signed manifest only after index
          mapping, closes Read around the measured original sealed inode and
          reuses that same inode without repeated lower content reads.
          Worker launch, passthrough, writable exposures and mount authority
          remain separate obligations.
          EOF
          printf '%s\n' PASS > "$out/result"
        '';
      }
    ];
  };
}
