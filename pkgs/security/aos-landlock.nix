##! aos-landlock — Apply package Landlock rules before exec
{
  mkDerivation,
  linux-headers,
}:
mkDerivation {
  pname = "aos-landlock";
  version = "0";
  src = null;

  buildDeps = [linux-headers];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "build";
      script = ''
        mkdir -p $out/bin
        $CC -O2 -Wall -Wextra -Werror \
          -I${linux-headers}/include \
          -o $out/bin/aos-landlock ${./aos-landlock.c}
      '';
    }
  ];

  passthru.evidenceSources = [
    (builtins.path {
      path = ./aos-landlock.nix;
      name = "aos-landlock.nix";
    })
    (builtins.path {
      path = ./aos-landlock.c;
      name = "aos-landlock.c";
    })
  ];

  checks = {
    testing,
    self,
    pkgs,
  }: {
    fs = testing.mkVMTest {
      name = "security-aos-landlock-fs";
      rootfsDeps = [
        self
        pkgs.coreutils
      ];
      testScript = ''
        abi=$(aos-landlock --print-abi)
        test "$abi" -ge 4
        echo "aos-landlock max ABI: $abi"

        mkdir -p /tmp/aos-landlock-allow /tmp/aos-landlock-deny
        printf original > /tmp/aos-landlock-exact-file

        aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /tmp/aos-landlock-allow \
          -- ${pkgs.coreutils}/bin/touch /tmp/aos-landlock-allow/ok
        test -f /tmp/aos-landlock-allow/ok

        aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /tmp/aos-landlock-exact-file \
          -- /bin/sh -c 'printf updated > /tmp/aos-landlock-exact-file'
        test "$(cat /tmp/aos-landlock-exact-file)" = updated

        aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /dev/null \
          -- /bin/sh -c 'printf quiet > /dev/null'

        aos-landlock --require-abi 4 \
          --network-unrestricted \
          --fs-ro / \
          --fs-rw /dev/null \
          -- /bin/sh -c 'printf unrestricted > /dev/null'

        if aos-landlock --network-unrestricted --tcp-bind 8080 \
          -- ${pkgs.coreutils}/bin/true; then
          echo "FAIL: aos-landlock accepted unrestricted networking with TCP rules" >&2
          exit 1
        fi

        if aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /tmp/aos-landlock-allow \
          -- ${pkgs.coreutils}/bin/touch /tmp/aos-landlock-deny/nope; then
          echo "FAIL: aos-landlock allowed write outside fs-rw grant" >&2
          exit 1
        fi

        printf readable > /tmp/aos-landlock-deny/readable
        aos-landlock --require-abi 4 \
          --fs-read / \
          --fs-ro /nix/store \
          -- ${pkgs.coreutils}/bin/cat /tmp/aos-landlock-deny/readable \
          > /dev/null

        # AOS coreutils dispatches by argv[0], so preserve the applet basename.
        mkdir /tmp/aos-landlock-deny/copied
        cp ${pkgs.coreutils}/bin/true /tmp/aos-landlock-deny/copied/true
        aos-landlock --require-abi 4 \
          --fs-ro / \
          -- /tmp/aos-landlock-deny/copied/true

        if aos-landlock --require-abi 4 \
          --fs-read / \
          --fs-ro /nix/store \
          -- /tmp/aos-landlock-deny/copied/true; then
          echo "FAIL: aos-landlock --fs-read unexpectedly granted execute" >&2
          exit 1
        fi

        echo "aos-landlock fs policy: PASS"
      '';
    };
  };

  meta = {
    description = "Apply package Landlock rules before exec";
    license = "MIT";
  };
}
