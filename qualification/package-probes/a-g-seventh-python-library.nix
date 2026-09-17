##! Exercises the seventh-slice A-G Python library through its public API.
{testing}: {
  distlib = testing.mkQualificationPackageProbe {
    name = "distlib";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "distlib";
      primary = {
        input = "A distribution name requiring canonical package-name normalization.";
        operation = "Import distlib from the package output and normalize the name through its public utility API.";
        expected = "Distlib converts runs of punctuation to the canonical hyphenated lowercase name.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import pathlib, sys
                module = next(pathlib.Path("@out@").rglob("distlib/__init__.py"))
                sys.path.insert(0, str(module.parent.parent))
                from distlib.util import normalize_name
                assert normalize_name("AOS.Sample_Package") == "aos-sample-package"
                print("distlib api passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "distlib api passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A version string containing spaces and no valid release segment.";
        operation = "Construct a normalized version through distlib's version API.";
        expected = "Distlib rejects the invalid normalized-version syntax.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import pathlib, sys
                module = next(pathlib.Path("@out@").rglob("distlib/__init__.py"))
                sys.path.insert(0, str(module.parent.parent))
                from distlib.version import NormalizedVersion, UnsupportedVersionError
                try:
                    NormalizedVersion("not a version")
                except UnsupportedVersionError:
                    sys.stderr.write("distlib rejected invalid input\n")
                    raise SystemExit(7)
                raise SystemExit(2)
              ''
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "distlib rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
