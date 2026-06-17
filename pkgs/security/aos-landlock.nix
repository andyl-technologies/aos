##! aos-landlock — Apply package Landlock TCP rules before exec
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

  meta = {
    description = "Apply package Landlock TCP rules before exec";
    license = "MIT";
  };
}
