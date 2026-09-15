##! Exercises Q-through-Z Python modules and runtime data through their public interfaces.
{testing}: let
  mkPythonProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryProgram,
    outputSitePackages ? false,
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

            ${
              if outputSitePackages
              then ''
                locations = glob.glob("@out@/lib/python*/site-packages")
                if len(locations) != 1:
                    raise RuntimeError("package does not expose one Python site-packages directory")
                sys.path.insert(0, locations[0])
              ''
              else ""
            }

            ${primaryProgram}
          '';
          steps = [
            {
              argv = ["@python@" "probe.py"];
              exit_code = 0;
              stdout.exact = "";
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

            ${
              if outputSitePackages
              then ''
                locations = glob.glob("@out@/lib/python*/site-packages")
                if len(locations) != 1:
                    raise RuntimeError("package does not expose one Python site-packages directory")
                sys.path.insert(0, locations[0])
              ''
              else ""
            }

            ${badProgram}
          '';
          steps = [
            {
              argv = ["@python@" "probe.py"];
              exit_code = 0;
              stdout.exact = "";
              stderr.exact = "";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  setuptools = mkPythonProbe {
    package = "setuptools";
    outputSitePackages = true;
    primaryInput = "The conventional true value 'yes'.";
    primaryOperation = "Load setuptools from the package output and parse the value with its distutils compatibility API.";
    primaryExpected = "strtobool accepts the value and returns integer 1.";
    primaryProgram = ''
      from setuptools._distutils.util import strtobool
      assert strtobool("yes") == 1
    '';
    badInput = "A boolean spelling outside the accepted value set.";
    badOperation = "Parse the unknown spelling with strtobool.";
    badExpected = "The API rejects the value with ValueError.";
    badProgram = ''
      from setuptools._distutils.util import strtobool
      try:
          strtobool("qualification-maybe")
      except ValueError:
          pass
      else:
          raise RuntimeError("setuptools accepted an invalid boolean value")
    '';
  };

  tzdata = mkPythonProbe {
    package = "tzdata";
    primaryInput = "The America/Los_Angeles zone and two UTC instants on opposite sides of the 2026 daylight transition.";
    primaryOperation = "Load the packaged TZif data with Python zoneinfo and inspect both offsets.";
    primaryExpected = "The zone reports UTC-08:00 in January and UTC-07:00 in July.";
    primaryProgram = ''
      from datetime import datetime, timezone, timedelta
      from zoneinfo import ZoneInfo, reset_tzpath
      reset_tzpath(["@out@/share/zoneinfo"])
      zone = ZoneInfo("America/Los_Angeles")
      assert datetime(2026, 1, 15, tzinfo=timezone.utc).astimezone(zone).utcoffset() == timedelta(hours=-8)
      assert datetime(2026, 7, 15, tzinfo=timezone.utc).astimezone(zone).utcoffset() == timedelta(hours=-7)
    '';
    badInput = "A time-zone key absent from the IANA database.";
    badOperation = "Resolve the nonexistent key from the packaged TZif tree.";
    badExpected = "ZoneInfo rejects the key with ZoneInfoNotFoundError.";
    badProgram = ''
      from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, reset_tzpath
      reset_tzpath(["@out@/share/zoneinfo"])
      try:
          ZoneInfo("Qualification/Zone-Does-Not-Exist")
      except ZoneInfoNotFoundError:
          pass
      else:
          raise RuntimeError("zoneinfo accepted a nonexistent zone")
    '';
  };
}
