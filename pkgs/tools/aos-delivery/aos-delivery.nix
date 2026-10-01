##! aos-delivery -- Application-owned signed-delivery API client and bundle builder.
{
  mkDerivation,
  python3,
  bash,
  coreutils,
  git,
  ca-certificates,
  buildPackages,
}:
mkDerivation {
  pname = "aos-delivery";
  version = "1";
  src = ./_src;
  buildDeps = [buildPackages.python3 buildPackages.git coreutils];
  runtimeDeps = [python3 bash git ca-certificates];
  phases = [
    {
      name = "unpack";
      script = ''
        cp -r "$src" source
        chmod -R u+w source
        cd source
      '';
    }
    {
      name = "check";
      script = ''
        ${buildPackages.python3}/bin/python3 -B -m unittest discover -s . -p '*_test.py'
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin" "$out/lib/aos-delivery"
        cp delivery.py transport.py artifact.py cargo_inventory.py "$out/lib/aos-delivery/"
        cat > "$out/bin/aos-delivery" <<EOF
        #!${bash}/bin/bash
        export SSL_CERT_FILE=${ca-certificates}/etc/ssl/certs/ca-certificates.crt
        export PATH=${git}/bin:\$PATH
        exec ${python3}/bin/python3 -B -E "$out/lib/aos-delivery/delivery.py" "\$@"
        EOF
        chmod +x "$out/bin/aos-delivery"
      '';
    }
  ];
  meta.description = "Typed API-only application staging delivery client";
}
