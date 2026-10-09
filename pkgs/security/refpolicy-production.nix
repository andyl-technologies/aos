##! Production-kernel-compatible SELinux Reference Policy modules.
{callPackage}:
callPackage ./refpolicy.nix {production = true;}
