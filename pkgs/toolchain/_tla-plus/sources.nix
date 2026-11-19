# Source pins for the third-party Java libraries bundled into tla2tools.jar.
#
# Upstream checks these libraries into tlatools/org.lamport.tlatools/lib/ as
# compiled JARs; the versions below match that directory for the pinned TLA+
# release. Each entry records the top-level directory of its archive so the
# build can extract only the module sources it compiles.
{fetchurl}: let
  github = repository: ref: hash:
    fetchurl {
      urls = ["https://codeload.github.com/${repository}/tar.gz/refs/tags/${ref}"];
      inherit hash;
    };
in {
  activation = rec {
    version = "1.2.1";
    dir = "jaf-api-${version}";
    src = github "jakartaee/jaf-api" version "sha256-xZNoZNLLwob4HiEEH81iC9EDs2DbjWvaNvjeevjC/ys=";
  };

  mail = rec {
    version = "1.6.8";
    dir = "mail-api-${version}";
    src = github "jakartaee/mail-api" version "sha256-ssf3JH37mvxOvL3tY65JKZN4FEHsT5blSs3aXXme5JQ=";
  };

  jline = rec {
    version = "3.25.0";
    dir = "jline3-jline-parent-${version}";
    src = github "jline/jline3" "jline-parent-${version}" "sha256-2VezFH3LFb7zhB8UcuRBMUwCgcwT1UHdGD/53Mme/Ok=";
  };

  # Optional jline-builtins dependency (charset detection in Nano). Upstream
  # leaves it out of tla2tools.jar, so it is only on the compile classpath.
  # The maintained fork keeps the org.mozilla.universalchardet API.
  juniversalchardet = rec {
    version = "2.5.2";
    dir = "juniversalchardet-${version}";
    src = github "albfernandez/juniversalchardet" "v${version}" "sha256-gR8zpyCqxwlpZafrPaSkwSdEBiyMCKeHwTXbs3xVzSQ=";
  };

  gson = rec {
    version = "2.14.0";
    dir = "gson-gson-parent-${version}";
    src = github "google/gson" "gson-parent-${version}" "sha256-WHsS6uElqRa5zvIhdpTe8qQnFTOfLyOb2MANJ4Oh2oI=";
  };

  # Compile-only annotations referenced by Gson.
  errorProneAnnotations = rec {
    version = "2.48.0";
    dir = "error-prone-${version}";
    src = github "google/error-prone" "v${version}" "sha256-XhgVSjG6BZ1TVxsa8KvjVyDDiEmhMfEUQ5iRLehXV6Q=";
  };

  lsp4j = rec {
    version = "0.21.1";
    dir = "lsp4j-${version}";
    src = github "eclipse-lsp4j/lsp4j" "v${version}" "sha256-f6d6kO70zNccdlWKITp98ifLvAgbF+iVUSivhEgT/N4=";
  };

  # The debug protocol classes are generated from DebugProtocol.xtend by the
  # Xtend compiler. Eclipse publishes the generated Java sources for each
  # release; compiling those avoids bootstrapping the Xtend toolchain.
  lsp4jDebugSources = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/eclipse/lsp4j/org.eclipse.lsp4j.debug/0.21.1/org.eclipse.lsp4j.debug-0.21.1-sources.jar"];
    hash = "sha256-LGNqgizWbU0hHEgTIqsZLBWAaBPNwVhKfKqSCgU8HEE=";
  };

  prettier4j = rec {
    version = "0.3.2";
    dir = "prettier4j-${version}";
    src = github "opencastsoftware/prettier4j" "v${version}" "sha256-xRHMZN8i2TZx5ngzm5qfQW4nlVtcTU34O2nLLiszx9E=";
  };

  # Compile-only annotations referenced by prettier4j.
  apiguardian = rec {
    version = "1.1.2";
    dir = "apiguardian-r${version}";
    src = github "apiguardian-team/apiguardian" "r${version}" "sha256-WWVYaLLzAYaK6FdF0+AD4X99dWCPnV2siHnD9dDpcOw=";
  };
}
