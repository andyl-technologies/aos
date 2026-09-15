##! samba-smbd — Narrow Samba file server for QEMU user networking
{callPackage}:
callPackage ./samba.nix {smbdOnly = true;}
