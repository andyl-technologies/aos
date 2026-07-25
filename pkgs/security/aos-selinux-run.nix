##! aos-selinux-run - Enter a SELinux context before exec
{mkDerivation}:
mkDerivation {
  pname = "aos-selinux-run";
  version = "0";
  src = null;

  buildDeps = [];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "build";
      script = ''
        mkdir -p $out/bin
        $CC -O2 -Wall -Wextra -Werror \
          -o $out/bin/aos-selinux-run ${./aos-selinux-run.c}
      '';
    }
  ];

  meta = {
    description = "Enter a SELinux context before exec";
    license = "MIT";
  };
}
