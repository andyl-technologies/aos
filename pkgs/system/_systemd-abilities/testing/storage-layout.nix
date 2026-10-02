##! Shares baked fleet disk sizes with the retained provisioning policy.
{
  varProvisioning ? "baked",
  varSizeMiB ? 256,
}: let
  checkedMode =
    if builtins.elem varProvisioning ["baked" "repart"]
    then varProvisioning
    else throw "systemd test storage requires baked or repart var provisioning";
  checkedVarSize =
    if builtins.isInt varSizeMiB && varSizeMiB > 0
    then varSizeMiB
    else throw "systemd test storage varSizeMiB must be a positive integer";
  baked = builtins.seq checkedVarSize (checkedMode == "baked");
  swapSizeMiB = 8;
  configurationSource = builtins.toFile "aos-baked-test-storage-${toString checkedVarSize}.nix" ''
    {lib, ...}: {
      # The baked fixture layout overrides production defaults. Authored host
      # policy remains stronger and must still match this completed disk.
      aos.provisioning.storage.partitions = {
        swap = {
          sizeMin = lib.mkOverride 900 "${toString swapSizeMiB}M";
          sizeMax = lib.mkOverride 900 "${toString swapSizeMiB}M";
          grow = lib.mkOverride 900 false;
        };
        var = {
          sizeMin = lib.mkOverride 900 "${toString checkedVarSize}M";
          sizeMax = lib.mkOverride 900 "${toString checkedVarSize}M";
          grow = lib.mkOverride 900 false;
        };
      };
    }
  '';
in {
  inherit baked swapSizeMiB;
  varSizeMiB = checkedVarSize;
  configurationSource =
    if baked
    then configurationSource
    else null;
}
