##! btrfs-progs — Btrfs filesystem utilities and library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  acl,
  attr,
  e2fsprogs,
  lzo,
  openssl,
  systemd,
  util-linux,
  zlib,
  zstd,
}: let
  version = "6.19.1";
in
  mkDerivation {
    pname = "btrfs-progs";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.edge.kernel.org/pub/linux/kernel/people/kdave/btrfs-progs/btrfs-progs-v${version}.tar.xz"];
      hash = "sha256-uyfh7FTnw8C3suWW+FOnPAej1y8hvJQEIHPCTb8EV5Y=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [
      acl
      attr
      e2fsprogs
      lzo
      openssl
      systemd
      util-linux
      zlib
      zstd
    ];
    propagatedDeps = [acl attr lzo openssl util-linux zlib zstd];

    configureFlags = builtins.concatStringsSep " " [
      # The release ships its complete reStructuredText manual sources, but
      # AOS does not yet package the Sphinx documentation toolchain.
      "--disable-documentation"
      "--disable-python"
      "--with-crypto=openssl"
      "--with-convert=ext2"
    ];
    makeFlags = "udevruledir=$out/lib/udev/rules.d";

    postInstall = ''
      mkdir -p "$out/share/bash-completion/completions"
      install -m 444 btrfs-completion "$out/share/bash-completion/completions/btrfs"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-btrfs-progs";
        tool = self;
        command = "truncate -s 128M /tmp/btrfs.img && mkfs.btrfs -q /tmp/btrfs.img && btrfs check --readonly /tmp/btrfs.img";
      };
    };

    meta = {
      description = "Userspace utilities and library for the Btrfs filesystem";
      homepage = "https://btrfs.readthedocs.io/";
      license = "GPL-2.0-only";
      mainProgram = "btrfs";
    };
  }
