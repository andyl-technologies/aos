##! Fixed private images for the existing Source and Cache view preparers.
{
  mkDerivation,
  bash,
  coreutils,
  util-linux,
}:
mkDerivation {
  pname = "aos-sandbox-view-preparer-tools";
  version = "1.0.0";
  src = null;

  buildDeps = [coreutils];
  runtimeDeps = [bash coreutils util-linux];
  propagatedDeps = [];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/libexec"

        # Distinct immutable inodes permit exact executable labels without
        # changing any shared interpreter/tool image's existing policy role.
        install -m 0555 ${bash}/bin/bash "$out/libexec/bash"
        for tool in stat mkdir chown; do
          install -m 0555 "${coreutils}/bin/$tool" "$out/libexec/$tool"
        done
        for tool in findmnt mount umount; do
          install -m 0555 "${util-linux}/bin/$tool" "$out/libexec/$tool"
        done
      '';
    }
  ];

  passthru = {
    interpreter = "libexec/bash";
    tools = ["stat" "mkdir" "chown" "findmnt" "mount" "umount"];
    evidenceSources = [
      (builtins.path {
        path = ./aos-sandbox-view-preparer-tools.nix;
        name = "aos-sandbox-view-preparer-tools.nix";
      })
      bash.src
      coreutils.src
      util-linux.src
    ];
  };

  meta = {
    description = "Exact private AOS interpreter/tool images for existing read-only view preparation";
    license = "GPL-3.0-or-later AND GPL-2.0-or-later";
  };
}
