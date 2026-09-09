##! workerd — Cloudflare's Workers runtime built from source.
##!
##! The public package name retains a small target-native launcher output while
##! `workerd-source` owns the Bazel build. Keeping the names separate preserves
##! existing package references and exposes the complete source build as an
##! independently auditable release artifact.
{
  mkDerivation,
  workerd-source,
}:
mkDerivation {
  pname = "workerd";
  version = workerd-source.version;
  src = null;

  buildDeps = [];
  runtimeDeps = [workerd-source];
  propagatedDeps = [];

  passthru.evidenceSources = workerd-source.passthru.evidenceSources;

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        ln -s "${workerd-source}/bin/workerd" "$out/bin/workerd"
      '';
    }
  ];

  meta = {
    description = "Cloudflare workerd Workers runtime built from source with AOS tools";
    homepage = "https://github.com/cloudflare/workerd";
    license = "Apache-2.0";
  };

  checks = {
    testing,
    self,
    pkgs,
  }: {
    version = testing.mkVMTest {
      name = "tools-workerd-version";
      rootfsDeps = [self];
      testScript = ''
        OUTPUT=$(workerd --version 2>&1)
        case "$OUTPUT" in
          *"2024-09-09"*)
            echo "==> workerd version: PASS ($OUTPUT)"
            ;;
          *)
            echo "==> ERROR: unexpected workerd version: $OUTPUT" >&2
            exit 1
            ;;
        esac
      '';
    };
  };
}
