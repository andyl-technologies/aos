##! Exercises additional H-through-P Python packages through their public APIs.
{testing}: let
  mkPythonProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryProgram,
    badInput,
    badOperation,
    badExpected,
    badProgram,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files."probe.py" = ''
            import glob
            import sys

            locations = glob.glob("@out@/lib/python*/site-packages")
            if len(locations) != 1:
                raise RuntimeError("package does not expose one site-packages directory")
            sys.path.insert(0, locations[0])

            ${primaryProgram}
            print("${package} primary passed")
          '';
          steps = [
            {
              argv = ["@python@" "probe.py"];
              exit_code = 0;
              stdout.exact = "${package} primary passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files."probe.py" = ''
            import glob
            import sys

            locations = glob.glob("@out@/lib/python*/site-packages")
            if len(locations) != 1:
                raise RuntimeError("package does not expose one site-packages directory")
            sys.path.insert(0, locations[0])

            ${badProgram}
            print("${package} rejected invalid input", file=sys.stderr)
            raise SystemExit(7)
          '';
          steps = [
            {
              argv = ["@python@" "probe.py"];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = "${package} rejected invalid input\n";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  packaging = mkPythonProbe {
    package = "packaging";
    primaryInput = "The normalized version text 1.2.3 and a lower prerelease.";
    primaryOperation = "Parse and compare both values through packaging.version.Version.";
    primaryExpected = "Version ordering places 1.2.3 after 1.2.3rc1.";
    primaryProgram = ''
      from packaging.version import Version
      assert Version("1.2.3") > Version("1.2.3rc1")
      assert str(Version("01.2.3")) == "1.2.3"
    '';
    badInput = "A version string containing no valid release segment.";
    badOperation = "Parse the malformed value through Version.";
    badExpected = "packaging raises InvalidVersion.";
    badProgram = ''
      from packaging.version import InvalidVersion, Version
      try:
          Version("qualification is not a version")
      except InvalidVersion:
          pass
      else:
          raise RuntimeError("packaging accepted an invalid version")
    '';
  };

  "python3-dbus" = mkPythonProbe {
    package = "python3-dbus";
    primaryInput = "The D-Bus signature a{sv} for a string-to-variant dictionary.";
    primaryOperation = "Parse and iterate the signature through dbus.Signature.";
    primaryExpected = "The signature contains one complete array type and round-trips unchanged.";
    primaryProgram = ''
      import dbus
      signature = dbus.Signature("a{sv}")
      assert str(signature) == "a{sv}"
      assert len(list(signature)) == 1
    '';
    badInput = "A D-Bus array signature with no element type.";
    badOperation = "Parse the incomplete signature through dbus.Signature.";
    badExpected = "dbus-python raises ValueError.";
    badProgram = ''
      import dbus
      try:
          dbus.Signature("a")
      except ValueError:
          pass
      else:
          raise RuntimeError("dbus-python accepted an incomplete signature")
    '';
  };

  "python3-markupsafe" = mkPythonProbe {
    package = "python3-markupsafe";
    primaryInput = "HTML markup containing an element and ampersand.";
    primaryOperation = "Escape the text through markupsafe.escape.";
    primaryExpected = "MarkupSafe emits the exact entity-escaped representation.";
    primaryProgram = ''
      from markupsafe import escape
      assert str(escape("<answer>42 & more</answer>")) == "&lt;answer&gt;42 &amp; more&lt;/answer&gt;"
    '';
    badInput = "A safe-format template containing an unsupported conversion specifier.";
    badOperation = "Format the malformed template through Markup.format.";
    badExpected = "MarkupSafe rejects the conversion with ValueError.";
    badProgram = ''
      from markupsafe import Markup
      try:
          Markup("{value!z}").format(value="answer")
      except ValueError:
          pass
      else:
          raise RuntimeError("MarkupSafe accepted an invalid conversion")
    '';
  };
}
