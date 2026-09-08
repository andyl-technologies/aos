##! Exercises sixth-slice A-G data and platform-support packages.
{testing}: let
  mkDataProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badScript,
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
          files = {};
          steps = [
            {
              argv = ["@python@" "-c" primaryScript];
              exit_code = 0;
              stdout.exact = "${package} data passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = {};
          steps = [
            {
              argv = ["@python@" "-c" badScript];
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

  mkClasspathProbe = package:
    mkDataProbe {
      inherit package;
      primaryInput = "The GNU Classpath standard-library archive.";
      primaryOperation = "Open the archive and inspect core Java class entries.";
      primaryExpected = "The archive is valid ZIP data containing Object, String, and ArrayList classes.";
      primaryScript = ''
        import pathlib, zipfile
        archive = next(pathlib.Path("@out@").rglob("glibj.zip"))
        with zipfile.ZipFile(archive) as jar:
            names = set(jar.namelist())
        assert {"java/lang/Object.class", "java/lang/String.class", "java/util/ArrayList.class"} <= names
        print("${package} data passed")
      '';
      badInput = "A request for a Java core class absent from the standard-library archive.";
      badOperation = "Resolve the nonexistent class entry in the archive index.";
      badExpected = "The archive lookup rejects the unknown class.";
      badScript = ''
        import pathlib, sys, zipfile
        archive = next(pathlib.Path("@out@").rglob("glibj.zip"))
        with zipfile.ZipFile(archive) as jar:
            if "java/lang/AosNonexistent.class" in jar.namelist():
                raise SystemExit(2)
        sys.stderr.write("${package} rejected invalid input\n")
        raise SystemExit(7)
      '';
    };
in {
  classpath-0_93 = mkClasspathProbe "classpath-0_93";
  classpath-0_99 = mkClasspathProbe "classpath-0_99";

  config-module-smoke = mkDataProbe {
    package = "config-module-smoke";
    primaryInput = "The package's fixed config-module payload and Bash dependency link.";
    primaryOperation = "Read the payload and resolve the declared dependency link.";
    primaryExpected = "The payload is exact and the Bash link resolves inside the store.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@/share/config-module-smoke")
      assert (root / "payload.txt").read_text() == "payload\n"
      assert (root / "bash").is_symlink() and (root / "bash").resolve().is_dir()
      print("config-module-smoke data passed")
    '';
    badInput = "A request for an undeclared config-module payload member.";
    badOperation = "Resolve that member beneath the package data directory.";
    badExpected = "The package data lookup rejects the absent member.";
    badScript = ''
      import pathlib, sys
      if pathlib.Path("@out@/share/config-module-smoke/absent").exists():
          raise SystemExit(2)
      sys.stderr.write("config-module-smoke rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  darwin-sdk = mkDataProbe {
    package = "darwin-sdk";
    primaryInput = "The assembled Darwin C headers and text-based libSystem stub.";
    primaryOperation = "Inspect the public stdio declarations and parse the TAPI library document.";
    primaryExpected = "The SDK exports FILE declarations and an install-name for libSystem.";
    primaryScript = ''
      import pathlib
      stdio = pathlib.Path("@out@/usr/include/stdio.h").read_text(errors="replace")
      tapi = pathlib.Path("@out@/usr/lib/libSystem.tbd").read_text()
      assert "FILE" in stdio and "printf" in stdio
      assert "install-name:" in tapi and "libSystem" in tapi
      print("darwin-sdk data passed")
    '';
    badInput = "A request for a framework header that the assembled SDK does not provide.";
    badOperation = "Resolve the nonexistent framework header beneath the SDK root.";
    badExpected = "The SDK lookup rejects the missing framework surface.";
    badScript = ''
      import pathlib, sys
      if pathlib.Path("@out@/System/Library/Frameworks/AosMissing.framework/Headers/AosMissing.h").exists():
          raise SystemExit(2)
      sys.stderr.write("darwin-sdk rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  desired-config-test = mkDataProbe {
    package = "desired-config-test";
    primaryInput = "The desired-configuration test package payload.";
    primaryOperation = "Read the installed package identity bytes.";
    primaryExpected = "The package contains its exact desired-config-test marker.";
    primaryScript = ''
      import pathlib
      assert pathlib.Path("@out@/share/desired-config-test/payload.txt").read_bytes() == b"desired-config-test"
      print("desired-config-test data passed")
    '';
    badInput = "A request for an undeclared generated configuration file in the immutable package.";
    badOperation = "Resolve that path beneath the package output.";
    badExpected = "The immutable package rejects the absent host-generated configuration.";
    badScript = ''
      import pathlib, sys
      if pathlib.Path("@out@/etc/aos/packages/desired-config-test/config.env").exists():
          raise SystemExit(2)
      sys.stderr.write("desired-config-test rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  desired-prune-test = mkDataProbe {
    package = "desired-prune-test";
    primaryInput = "The desired-pruning test package payload.";
    primaryOperation = "Read the installed package identity bytes.";
    primaryExpected = "The package contains its exact desired-prune-test marker.";
    primaryScript = ''
      import pathlib
      assert pathlib.Path("@out@/share/desired-prune-test/payload.txt").read_bytes() == b"desired-prune-test"
      print("desired-prune-test data passed")
    '';
    badInput = "A request for mutable service state inside the immutable package output.";
    badOperation = "Resolve the nonexistent state marker beneath the package output.";
    badExpected = "The immutable package rejects the absent runtime-state path.";
    badScript = ''
      import pathlib, sys
      if pathlib.Path("@out@/var/lib/aos-pkg-desired-prune-test/started").exists():
          raise SystemExit(2)
      sys.stderr.write("desired-prune-test rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  docbook-xml = mkDataProbe {
    package = "docbook-xml";
    primaryInput = "The DocBook 4.5 XML catalog and document type definition.";
    primaryOperation = "Parse the catalog and inspect the book element declaration.";
    primaryExpected = "The catalog is well-formed and its DTD declares the DocBook book element.";
    primaryScript = ''
      import pathlib, xml.etree.ElementTree as ET
      root = pathlib.Path("@out@/share/xml/docbook/schema/dtd/4.5")
      ET.parse(root / "catalog.xml")
      assert "<!ELEMENT book" in (root / "docbookx.dtd").read_text(errors="replace")
      print("docbook-xml data passed")
    '';
    badInput = "A request for an element declaration absent from DocBook 4.5.";
    badOperation = "Search the installed DTD for the nonexistent declaration.";
    badExpected = "The DTD lookup rejects the unknown element.";
    badScript = ''
      import pathlib, sys
      source = pathlib.Path("@out@/share/xml/docbook/schema/dtd/4.5/docbookx.dtd").read_text(errors="replace")
      if "<!ELEMENT aos-nonexistent" in source:
          raise SystemExit(2)
      sys.stderr.write("docbook-xml rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  docbook-xsl = mkDataProbe {
    package = "docbook-xsl";
    primaryInput = "The DocBook stylesheet catalog and XHTML transformation entry point.";
    primaryOperation = "Parse both XML documents and inspect the catalog rewrite rules.";
    primaryExpected = "The catalog maps current DocBook stylesheet URIs to the installed tree.";
    primaryScript = ''
      import pathlib, xml.etree.ElementTree as ET
      root = pathlib.Path("@out@/share/xml/docbook/stylesheet")
      catalog = ET.parse(root / "catalog.xml").getroot()
      ET.parse(root / "docbook-xsl/xhtml/docbook.xsl")
      rules = list(catalog)
      assert any("docbook.sourceforge.net/release/xsl/current/" in value for rule in rules for value in rule.attrib.values())
      print("docbook-xsl data passed")
    '';
    badInput = "A request for an output-family stylesheet absent from the installed tree.";
    badOperation = "Resolve the nonexistent stylesheet entry point.";
    badExpected = "The stylesheet lookup rejects the unknown output family.";
    badScript = ''
      import pathlib, sys
      if pathlib.Path("@out@/share/xml/docbook/stylesheet/docbook-xsl/aos-output/docbook.xsl").exists():
          raise SystemExit(2)
      sys.stderr.write("docbook-xsl rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  edk2 = mkDataProbe {
    package = "edk2";
    primaryInput = "The architecture-specific EDK2 flash-volume images.";
    primaryOperation = "Inspect every installed firmware image for its firmware-volume signature.";
    primaryExpected = "At least one nonempty flash image carries an FVH signature near its volume header.";
    primaryScript = ''
      import pathlib
      images = sorted(pathlib.Path("@out@/FV").glob("*.fd"))
      assert images
      assert all(image.stat().st_size > 1024 * 1024 for image in images)
      assert all(b"_FVH" in image.read_bytes()[:4096] for image in images)
      print("edk2 data passed")
    '';
    badInput = "A request for an architecture-neutral EDK2 flash image that is not produced.";
    badOperation = "Resolve that undeclared firmware artifact.";
    badExpected = "The firmware inventory rejects the absent image name.";
    badScript = ''
      import pathlib, sys
      if pathlib.Path("@out@/FV/AOS_GENERIC.fd").exists():
          raise SystemExit(2)
      sys.stderr.write("edk2 rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  firmware = mkDataProbe {
    package = "firmware";
    primaryInput = "The selected Linux firmware tree and its WHENCE inventory.";
    primaryOperation = "Read the inventory and verify that installed payload families contain regular files.";
    primaryExpected = "WHENCE identifies upstream firmware and the selected tree contains many payload files.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@/lib/firmware")
      whence = (root / "WHENCE").read_text(errors="replace")
      files = [path for path in root.rglob("*") if path.is_file() and path.name != "WHENCE"]
      assert "Driver:" in whence and "File:" in whence and len(files) > 10
      print("firmware data passed")
    '';
    badInput = "A request for a firmware payload name absent from the selected tree.";
    badOperation = "Resolve the nonexistent payload beneath the firmware root.";
    badExpected = "The firmware lookup rejects the unknown payload.";
    badScript = ''
      import pathlib, sys
      if pathlib.Path("@out@/lib/firmware/aos/nonexistent.bin").exists():
          raise SystemExit(2)
      sys.stderr.write("firmware rejected invalid input\n")
      raise SystemExit(7)
    '';
  };
}
