##! Checks proxy selection and malformed configuration through libproxy's CLI.
{testing}: let
  query = proxy: [
    "@bash@"
    "-c"
    ''
      unset no_proxy NO_PROXY PX_DEBUG G_MESSAGES_DEBUG
      # Resolve with the package's GIO modules, independent of the desktop session.
      unset GIO_EXTRA_MODULES GIO_MODULE_DIR
      export PX_FORCE_CONFIG=config-env
      export http_proxy="$1"
      exec "$2/bin/proxy" http://qualification.example/resource
    ''
    "libproxy-qualification"
    proxy
    "@out@"
  ];
in {
  libproxy = testing.mkQualificationPackageProbe {
    name = "libproxy";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "libproxy";
      primary = {
        input = "An HTTP URL and an explicit environment proxy endpoint.";
        operation = "Resolve the URL through the environment configuration backend.";
        expected = "The configured proxy endpoint is returned exactly.";
        files = {};
        steps = [
          {
            argv = query "http://127.0.0.1:3128";
            exit_code = 0;
            stdout.exact = "http://127.0.0.1:3128\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A proxy URI with an unterminated bracketed host.";
        operation = "Resolve the same URL with the malformed proxy configuration.";
        expected = "The invalid proxy is discarded and the documented direct connection fallback is returned.";
        files = {};
        steps = [
          {
            argv = query "http://[broken";
            exit_code = 0;
            stdout.exact = "direct://\n";
            stderr.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
