# Build-time immutable corpus authoring; this output never issues runtime credit.
{
  pkgs,
  lib,
  nativeCount,
  servicePolicy,
  sqliteBootstrapProof,
  campaignPolicy,
  componentAuthorities,
  guestAssets,
}: let
  source = import ./_source.nix {inherit lib;};
  authoredServicePolicy = pkgs.writeTextFile {
    name = "crucible-measurement-service-policy.json";
    text = builtins.toJSON servicePolicy;
  };
  authoredGuestAssets = pkgs.writeTextFile {
    name = "crucible-measurement-guest-assets.json";
    text = builtins.toJSON guestAssets;
  };
  guestAssetRoots =
    [guestAssets.kernel guestAssets.rootImage]
    ++ lib.optional (guestAssets.initrd.kind == "present") guestAssets.initrd.path;
  generator = import ./_measurement-workflow-author.nix {inherit pkgs lib;};
in
  assert builtins.elem nativeCount [1 2 4];
  assert pkgs.qemu-crucible.passthru.qemuBuildIdentity == pkgs.qemu-crucible-source.passthru.qemuBuildIdentity;
    pkgs.mkDerivation {
      pname = "crucible-private-resident-workflow";
      version = "0";
      src = null;
      buildDeps = [generator];
      runtimeDeps = [pkgs.crucible pkgs.qemu-crucible-source sqliteBootstrapProof campaignPolicy componentAuthorities] ++ guestAssetRoots;
      phases = [
        {
          name = "author-fixed-compact-corpus";
          script = ''
            mkdir -p "$out/share/crucible" "$out/nix-support"
            ${generator}/bin/crucible-measurement-workflow \
              "$out/share/crucible/resident-workflow" ${toString nativeCount} \
              ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
              ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
              ${authoredServicePolicy} \
              ${sqliteBootstrapProof}/share/crucible/sqlite-bootstrap/target.json \
              ${campaignPolicy} \
              ${componentAuthorities} \
              ${authoredGuestAssets}
            ln -s ${source} "$out/source"
            ln -s ${pkgs.crucible} "$out/suite"
            ln -s ${pkgs.qemu-crucible-source} "$out/corresponding-source"
            cat > "$out/nix-support/aos-release-policy" <<'POLICY'
            policy_version=1
            artifact_role=private-test-fixture
            standalone_release=false
            POLICY
          '';
        }
      ];
      passthru = {
        inherit nativeCount generator servicePolicy sqliteBootstrapProof campaignPolicy componentAuthorities guestAssets;
        privateFixture = true;
        runtimeAdmission = false;
        sourceCohort = source;
      };
    }
