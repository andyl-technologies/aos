##! Exercises python3-dbusmock through its public private-bus API.
{testing}: let
  pythonPathSetup = ''
    import json, os, pathlib, sys
    closure = json.loads(os.environ["AOS_QUALIFICATION_PACKAGE_CLOSURE"])
    site_directories = []
    executable_directories = []
    for root_text in closure:
        root = pathlib.Path(root_text)
        site = root / "lib/python3.14/site-packages"
        binaries = root / "bin"
        if site.is_dir():
            site_directories.append(str(site))
        if binaries.is_dir():
            executable_directories.append(str(binaries))
    sys.path[:0] = site_directories
    os.environ["PATH"] = os.pathsep.join(executable_directories)
  '';
in {
  python3-dbusmock = testing.mkQualificationPackageProbe {
    name = "python3-dbusmock";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "python3-dbusmock";
      primary = {
        input = "A private session bus managed by python3-dbusmock.";
        operation = "Start the bus, connect through its public BusType API, and inspect its registered names.";
        expected = "The private daemon accepts a connection and owns the standard D-Bus service name.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                ${pythonPathSetup}
                from dbusmock import BusType, PrivateDBus
                with PrivateDBus(BusType.SESSION):
                    connection = BusType.SESSION.get_connection()
                    names = connection.list_names()
                    connection.close()
                assert "org.freedesktop.DBus" in names
                print("python3-dbusmock operation passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "python3-dbusmock operation passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A request to enable a service absent from the configured D-Bus data directories.";
        operation = "Resolve the missing service through PrivateDBus.enable_service.";
        expected = "Python-dbusmock rejects the request without creating a service link.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                ${pythonPathSetup}
                import pathlib, sys
                from dbusmock import BusType, PrivateDBus
                os.environ["XDG_DATA_DIRS"] = str(pathlib.Path("empty-data").resolve())
                bus = PrivateDBus(BusType.SESSION)
                try:
                    bus.enable_service("org.example.QualificationMissing")
                except AssertionError as error:
                    assert "Service org.example.QualificationMissing not found" in str(error)
                else:
                    raise AssertionError("missing service was accepted")
                finally:
                    bus.stop()
                sys.stderr.write("python3-dbusmock rejected invalid input\n")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "python3-dbusmock rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
