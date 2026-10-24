##! Bounded native process-image closure auditor
{
  mkDerivation,
  python3,
  bash,
  dmtcp,
}:
mkDerivation {
  pname = "gem5-process-image-inventory";
  version = "1";
  platformSupport = {
    build = [
      {
        abi = ["gnu"];
        cpu = ["x86_64"];
        os = ["linux"];
      }
    ];
    host = [
      {
        abi = ["gnu"];
        cpu = ["x86_64"];
        os = ["linux"];
      }
    ];
    target = [];
    role = "public-package";
  };
  buildDeps = [python3 dmtcp];
  runtimeDeps = [python3 bash];
  phases = [
    {
      name = "check";
      script = ''
        export PYTHONDONTWRITEBYTECODE=1
        ${python3}/bin/python3 ${./_gem5/process-image-inventory-check.py} \
          ${./_gem5/process-image-inventory.py}
        ${python3}/bin/python3 ${./_gem5/process-image-context-check.py} \
          ${dmtcp} ${./_gem5/process-image-inventory.py}
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin" "$out/libexec"
        cp ${./_gem5/process-image-inventory.py} "$out/libexec/process-image-inventory.py"
        cat > "$out/bin/gem5-process-image-inventory" <<EOF
        #!${bash}/bin/bash
        exec ${python3}/bin/python3 "$out/libexec/process-image-inventory.py" "\$@"
        EOF
        chmod +x "$out/bin/gem5-process-image-inventory"
      '';
    }
  ];
}
