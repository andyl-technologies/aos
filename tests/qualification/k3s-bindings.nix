##! Exercises independent staged K3s artifact selection without starting guests.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-qualification-k3s-bindings";
  version = "1";
  src = null;
  buildDeps = [pkgs.buildPackages.python3];
  phases = [
    {
      name = "check";
      script = ''
        mkdir -p modules "$out"
        cp ${../../lib/testing/qualification_k3s_bindings.py} modules/qualification_k3s_bindings.py
        cp ${../../lib/testing/qualification_k3s_oci.py} modules/qualification_k3s_oci.py
        PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$PWD/modules \
          python3 ${./k3s-bindings.py}
        PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$PWD/modules \
          python3 ${./k3s-oci.py}
        printf '%s\n' 'Staged K3s binding rejection checks passed.' > "$out/result"
      '';
    }
  ];
}
