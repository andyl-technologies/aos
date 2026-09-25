##! Domain option schemas composed for package self-evaluation.
##!
##! Each schema remains owned by the host feature that consumes it. This
##! composition module gives package-authored modules the same option surface
##! when they are evaluated independently to produce package contracts.
{
  imports = [
    ./abilities/storage.nix
    ./base/_evaluation-mode.nix
    ./base/_filesystem-tree-options.nix
    ./base/_initrd-runtime-options.nix
    ./base/_kernel-package-options.nix
    ./base/_kernel-command-line-options.nix
    ./base/_manager-selection.nix
    ./base/_pam-service-options.nix
  ];
}
