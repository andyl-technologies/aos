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

        aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /tmp/aos-landlock-allow \
          -- ${pkgs.coreutils}/bin/touch /tmp/aos-landlock-allow/ok
        test -f /tmp/aos-landlock-allow/ok

        if aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /tmp/aos-landlock-allow \
          -- ${pkgs.coreutils}/bin/touch /tmp/aos-landlock-deny/nope; then
          echo "FAIL: aos-landlock allowed write outside fs-rw grant" >&2
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
