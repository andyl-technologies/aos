##! Exercises H-through-P data packages through deterministic database queries.
{testing}: let
  mkDataProbe = {
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
          files."query.py" = primaryProgram;
          steps = [
            {
              argv = ["@python@" "query.py"];
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
          files."query.py" = badProgram;
          steps = [
            {
              argv = ["@python@" "query.py"];
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
  hwdata = mkDataProbe {
    package = "hwdata";
    primaryInput = "PCI vendor identifier 8086.";
    primaryOperation = "Query the packaged pci.ids database for the vendor record.";
    primaryExpected = "The database maps the identifier to Intel Corporation.";
    primaryProgram = ''
      import pathlib
      import re

      database = pathlib.Path("@out@/share/hwdata/pci.ids").read_text()
      vendors = dict(re.findall(r"^([0-9a-f]{4})  (.+)$", database, re.MULTILINE))
      if vendors.get("8086") != "Intel Corporation":
          raise RuntimeError("PCI vendor 8086 did not resolve to Intel Corporation")
      print("hwdata primary passed")
    '';
    badInput = "PCI vendor identifier 0000, which is outside the assigned vendor records.";
    badOperation = "Query the packaged pci.ids vendor index for the unassigned identifier.";
    badExpected = "The lookup returns no vendor record and the probe records rejection.";
    badProgram = ''
      import pathlib
      import re
      import sys

      database = pathlib.Path("@out@/share/hwdata/pci.ids").read_text()
      vendors = dict(re.findall(r"^([0-9a-f]{4})  (.+)$", database, re.MULTILINE))
      if "0000" in vendors:
          raise RuntimeError("unassigned PCI vendor identifier appeared in the database")
      print("hwdata rejected invalid input", file=sys.stderr)
      raise SystemExit(7)
    '';
  };

  "publicsuffix-list" = mkDataProbe {
    package = "publicsuffix-list";
    primaryInput = "The domain www.example.co.uk.";
    primaryOperation = "Apply exact and wildcard rules from the packaged public suffix list.";
    primaryExpected = "The public suffix is co.uk and the registrable domain is example.co.uk.";
    primaryProgram = ''
      import pathlib

      rules = {
          line.strip()
          for line in pathlib.Path("@out@/share/publicsuffix/public_suffix_list.dat").read_text().splitlines()
          if line.strip() and not line.startswith("//")
      }

      labels = "www.example.co.uk".split(".")
      matches = []
      for offset in range(len(labels)):
          candidate = ".".join(labels[offset:])
          if candidate in rules:
              matches.append((len(labels) - offset, candidate))
          if offset and "*." + ".".join(labels[offset + 1:]) in rules:
              matches.append((len(labels) - offset, candidate))
      suffix_length, suffix = max(matches, default=(1, labels[-1]))
      registrable = ".".join(labels[-(suffix_length + 1):])
      if suffix != "co.uk" or registrable != "example.co.uk":
          raise RuntimeError("public suffix query returned an unexpected boundary")
      print("publicsuffix-list primary passed")
    '';
    badInput = "A domain containing an empty label between two dots.";
    badOperation = "Validate the domain labels before querying the suffix database.";
    badExpected = "The query rejects the malformed domain before assigning a suffix.";
    badProgram = ''
      import pathlib
      import sys

      pathlib.Path("@out@/share/publicsuffix/public_suffix_list.dat").read_text()
      labels = "example..com".split(".")
      if all(labels):
          raise RuntimeError("malformed domain unexpectedly passed label validation")
      print("publicsuffix-list rejected invalid input", file=sys.stderr)
      raise SystemExit(7)
    '';
  };
}
