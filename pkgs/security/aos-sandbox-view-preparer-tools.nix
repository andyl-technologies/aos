##! Fixed private images for the existing Source and Cache view preparers.
{
  mkDerivation,
  bash,
  coreutils,
  libselinux,
  ncurses,
  patchelf,
  pcre2,
  util-linux,
}:
mkDerivation {
  platformSupport = {
    build = [
      {
        abi = ["gnu"];
        os = ["linux"];
      }
    ];
    host = [
      {
        abi = ["gnu"];
        cpu = ["x86_64" "aarch64"];
        os = ["linux"];
      }
    ];
    target = [];
    role = "public-package";
  };
  pname = "aos-sandbox-view-preparer-tools";
  version = "1.0.0";
  src = null;

  buildDeps = [coreutils patchelf];
  # Copied ELF images retain direct references to these libraries. Listing
  # only their original executable packages lets reference scrubbing erase
  # Bash's Ncurses and Util-linux's SELinux runpaths.
  runtimeDeps = [bash coreutils libselinux ncurses pcre2 util-linux];
  propagatedDeps = [];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/libexec" "$out/lib"

        # Distinct immutable inodes permit exact executable labels without
        # changing any shared interpreter/tool image's existing policy role.
        install -m 0755 ${bash}/bin/bash "$out/libexec/bash"
        for tool in stat mkdir chown; do
          install -m 0755 "${coreutils}/bin/$tool" "$out/libexec/$tool"
        done
        for tool in findmnt mount umount; do
          install -m 0755 "${util-linux}/bin/$tool" "$out/libexec/$tool"
        done

        # The confined roles can read library inodes but cannot traverse the
        # store's usr_t SONAME symlinks. Keep the complete non-libc dependency
        # group as regular private files, including Libselinux's PCRE2 edge.
        install -m 0755 ${ncurses}/lib/libncursesw.so.6 "$out/lib/libncursesw.so.6"
        install -m 0755 ${libselinux}/lib/libselinux.so.1 "$out/lib/libselinux.so.1"
        install -m 0755 ${pcre2}/lib/libpcre2-8.so.0 "$out/lib/libpcre2-8.so.0"
        for library in libmount.so.1 libblkid.so.1 libsmartcols.so.1; do
          install -m 0755 "${util-linux}/lib/$library" "$out/lib/$library"
        done

        # Pin both direct and transitive edges. Rewriting only Bash's runpath
        # leaves the mount tools and Libselinux looking up shared symlinks.
        for image in "$out/libexec/bash" "$out/libexec/findmnt" \
            "$out/libexec/mount" "$out/libexec/umount" "$out"/lib/*; do
          for library in "$out"/lib/*; do
            ${patchelf}/bin/patchelf --replace-needed "''${library##*/}" "$library" "$image"
          done
        done

        chmod 0555 "$out"/libexec/* "$out"/lib/*
      '';
    }
  ];

  passthru = {
    interpreter = "libexec/bash";
    tools = ["stat" "mkdir" "chown" "findmnt" "mount" "umount"];
    evidenceSources =
      [
        (builtins.path {
          path = ./aos-sandbox-view-preparer-tools.nix;
          name = "aos-sandbox-view-preparer-tools.nix";
        })
      ]
      ++ bash.passthru.evidenceSources
      # The unmodified target Coreutils recipe has no separate source bundle.
      # Native Coreutils supplies its actual GCC16 construction evidence.
      ++ (coreutils.passthru.evidenceSources or [
        coreutils.src
        (builtins.path {
          path = ../base/coreutils.nix;
          name = "coreutils.nix";
        })
      ])
      ++ util-linux.passthru.evidenceSources;
  };

  meta = {
    description = "Exact private AOS interpreter/tool images for existing read-only view preparation";
    license = "GPL-3.0-or-later AND GPL-2.0-or-later";
  };
}
