##! Exercises the eighth-slice Crucible fixture package as a data contract.
{testing}: {
  crucible-fixtures = testing.mkQualificationPackageProbe {
    name = "crucible-fixtures";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "crucible-fixtures";
      primary = {
        input = "The deterministic Crucible fixture manifest, entropy seed, and root image.";
        operation = "Parse the manifest and verify its declared image digest and fixed seed size.";
        expected = "The root image matches its manifest digest and the entropy seed is exactly 32 bytes.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import hashlib, pathlib, tomllib
                root = pathlib.Path("@out@/share/crucible/fixtures")
                manifest = tomllib.loads((root / "manifest.toml").read_text())
                image = pathlib.Path("@out@") / manifest["fixture"]["root_image"]
                digest = hashlib.sha256(image.read_bytes()).hexdigest()
                assert digest == manifest["fixture"]["root_image_sha256"]
                seed = pathlib.Path("@out@") / manifest["entropy"]["seed_artifact"]
                assert len(seed.read_bytes()) == 32
                print("crucible-fixtures data passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "crucible-fixtures data passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A request for a mutable copy-on-write overlay inside the immutable fixture package.";
        operation = "Resolve the runtime overlay path beneath the fixture tree.";
        expected = "The package rejects the absent mutable overlay artifact.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import pathlib, sys
                if pathlib.Path("@out@/share/crucible/fixtures/root/aos-minimal-overlay.qcow2").exists():
                    raise SystemExit(2)
                sys.stderr.write("crucible-fixtures rejected invalid input\n")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "crucible-fixtures rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
