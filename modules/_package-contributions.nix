##! Package contribution schemas composed for package self-evaluation.
##!
##! Each schema remains owned by the host feature that consumes it. This
##! composition module gives package-authored modules the same option surface
##! when they are evaluated independently to produce package contracts.
{
  imports = [
    ./abilities/storage.nix
    ./base/_filesystem-tree-contributions.nix
    ./base/_initrd-runtime-artifact-contributions.nix
    ./base/_kernel-parameter-contributions.nix
    ./base/_manager-contributions.nix
    ./base/_pam-contributions.nix
    ./base/_runtime-check-contributions.nix
  ];
}
