##! Source-built ASM JARs required by the Bazel 7 bootstrap distribution.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  archives = [
    {
      version = "9.2";
      component = "asm";
      hash = "sha256-gegHAQYx8OgHSw+4XoCv1u+71+SzaUqtGelEwXGYD7c=";
    }
    {
      version = "9.2";
      component = "asm-tree";
      hash = "sha256-w1vFtLbFS/FavsNKuCHPnQgBpkRR9PYHDZPcuHEiqgg=";
    }
    {
      version = "9.2";
      component = "asm-analysis";
      hash = "sha256-xaZ2S7zunkvNjuHqM4CPlri1hzcfMpqnWi9UHy7hsNU=";
    }
    {
      version = "9.2";
      component = "asm-commons";
      hash = "sha256-bZiDkTa+RdWx/9yg/SZH646vks/1dmSMu/lvCK/T7W0=";
    }
    {
      version = "9.2";
      component = "asm-util";
      hash = "sha256-tjHUVhok6E6u7iwEla3e0hTklh7TKLAjAPfZsfQHyFM=";
    }
    {
      version = "9.6";
      component = "asm";
      hash = "sha256-K24S8No9BlumKKAkqIUasNW101AdrPzBh2kkMlD0934=";
    }
    {
      version = "9.6";
      component = "asm-tree";
      hash = "sha256-4vS+re8cMgPk0A9kYFxK0J14+0X8bJTsNkl9Y+azeWk=";
    }
    {
      version = "9.6";
      component = "asm-analysis";
      hash = "sha256-eUKd7qMFJURIecgnvYXCrKGhvt2P3a4wlvR+Ap81bcQ=";
    }
    {
      version = "9.6";
      component = "asm-commons";
      hash = "sha256-51cHAUWrBMfGh0BCkzt9hgBFa1/bzy0CKmzQqG5aRKE=";
    }
    {
      version = "9.6";
      component = "asm-util";
      hash = "sha256-59txW4vER1HZml8MAsghmq41WSFGKhasynJ2YzjBQoc=";
    }
  ];

  sources =
    builtins.map (
      archive:
        archive
        // {
          src = fetchurl {
            urls = [
              "https://repo.maven.apache.org/maven2/org/ow2/asm/${archive.component}/${archive.version}/${archive.component}-${archive.version}-sources.jar"
            ];
            inherit (archive) hash;
          };
        }
    )
    archives;

  unpackSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p "source-${source.version}-${source.component}"
      unzip -q ${source.src} -d "source-${source.version}-${source.component}"
    '')
    sources);

  buildJdk = buildPackages.openjdk-17;

  licenseSource = fetchurl {
    urls = ["https://gitlab.ow2.org/asm/asm/-/raw/85cf1aeb0d08be8446f6efbda962817d2a9707dd/LICENSE.txt"];
    hash = "sha256-KTtq83Hu4osP8W8DNOoZ4go9VSIUP6pLlbNGhVUHh5o=";
  };
in
  mkDerivation {
    pname = "bazel-asm";
    version = "9.2+9.6";
    src = (builtins.head sources).src;

    buildDeps = [
      buildJdk
      buildPackages.unzip
      buildPackages.findutils
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = unpackSources;
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME="${buildJdk}"
          export PATH="${buildJdk}/bin:$PATH"

          mkdir -p jars
          for version in 9.2 9.6; do
            classpath=
            for component in asm asm-tree asm-analysis asm-commons asm-util; do
              class_dir="classes-$version-$component"
              mkdir -p "$class_dir"

              find "source-$version-$component" -name '*.java' \
                ! -name module-info.java -print > "sources-$version-$component"
              if test -n "$classpath"; then
                javac -source 8 -target 8 -cp "$classpath" \
                  -d "$class_dir" @"sources-$version-$component"
              else
                javac -source 8 -target 8 \
                  -d "$class_dir" @"sources-$version-$component"
              fi

              jar --create --file "jars/$component-$version.jar" --no-manifest \
                --date=1980-01-01T00:00:02Z -C "$class_dir" .
              classpath="$class_dir''${classpath:+:$classpath}"
            done
          done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java" "$out/share/licenses/bazel-asm"
          cp jars/*.jar "$out/share/java/"
          cp ${licenseSource} "$out/share/licenses/bazel-asm/LICENSE.txt"
        '';
      }
    ];

    meta = {
      description = "ASM 9.2 and 9.6 bytecode libraries built from source for Bazel";
      homepage = "https://asm.ow2.io";
      license = "BSD-3-Clause";
    };
  }
