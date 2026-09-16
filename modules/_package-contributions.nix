##! Package contribution schemas composed for package self-evaluation.
##!
##! Each schema remains owned by the host feature that consumes it. This
##! composition module gives package-authored modules the same option surface
##! when they are evaluated independently to produce package contracts.
{
  imports = [
    ./base/_filesystem-tree-contributions.nix
    ./base/_kernel-parameter-contributions.nix
    ./base/_pam-contributions.nix
    ./base/_runtime-check-contributions.nix
    ./security/_wrapper-contributions.nix
  ];
}
