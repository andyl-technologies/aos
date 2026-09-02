##! lib/containers/publication-inputs.nix -- Unsigned publication bundle
##!
##! Packages one exact OCI subject and its deterministic evidence as the
##! complete non-secret input to the external container signing boundary.
{
  pkgs,
  pname,
  index,
  evidenceLayout,
}:
pkgs.mkDerivation {
  inherit pname;
  version = "1";
  src = null;
  buildDeps = [pkgs.coreutils index evidenceLayout];
  outputChecks.out = {};
  unsafeDiscardReferences.out = true;
  phases = [
    {
      name = "assemble";
      script = ''
        set -eu
        mkdir -p "$out"

        cp -R ${index}/layout "$out/oci-layout"
        cp ${index}/image.oci.tar "$out/image.oci.tar"
        cp -R ${evidenceLayout}/layout "$out/evidence-layout"
        cp ${evidenceLayout}/evidence.oci.tar "$out/evidence.oci.tar"
        cp ${evidenceLayout}/signature-input.json "$out/signature-input.json"
        cp ${evidenceLayout}/signing-request.json "$out/signing-request.json"
        cp ${evidenceLayout}/publication-roots.json "$out/publication-roots.json"

        printf '%s\n' \
          'This is an unsigned production publication-input bundle.' \
          'An external signer must add the DSSE object and emit the final signed OCI layout and container-release.json.' \
          > "$out/EXTERNAL-SIGNING-REQUIRED"
      '';
    }
  ];
  meta.description = "Unsigned external container-signing inputs";
}
