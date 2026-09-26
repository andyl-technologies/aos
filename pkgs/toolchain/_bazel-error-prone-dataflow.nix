##! Error Prone's relocated Dataflow library built from its Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
}: let
  version = "3.41.0-eisop1";
  buildJdk = buildPackages.openjdk-17;
  eisopRevision = "c08538fbc8e167a931cbe405614b52663a8e67be";

  sourceArchives = [
    {
      name = "dataflow-errorprone";
      url = "https://repo.maven.apache.org/maven2/io/github/eisop/dataflow-errorprone/${version}/dataflow-errorprone-${version}-sources.jar";
      hash = "sha256-vKEKGB5TP9RzCTIMNBUsadQ+AZKPC6wYgY41LcwLd+4=";
    }
    {
      name = "javacutil";
      url = "https://repo.maven.apache.org/maven2/org/checkerframework/javacutil/3.41.0/javacutil-3.41.0-sources.jar";
      hash = "sha256-7D6Ul5i0zDgB+HpReAnnNP9ZJ8NKIbWMuSDAUJOy5UE=";
    }
    {
      name = "checker-qual";
      url = "https://repo.maven.apache.org/maven2/org/checkerframework/checker-qual/3.41.0/checker-qual-3.41.0-sources.jar";
      hash = "sha256-gwgiC73U4StJ+gapHeaF+vnMGjdkZEeMgIRb4+h7fU8=";
    }
    {
      name = "plume-util";
      url = "https://repo.maven.apache.org/maven2/org/plumelib/plume-util/1.8.1/plume-util-1.8.1-sources.jar";
      hash = "sha256-fUVs+38EF6Bq+Ca9a/wCr2yJe9R80UBo2+TKx2t1NXs=";
    }
    {
      name = "hashmap-util";
      url = "https://repo.maven.apache.org/maven2/org/plumelib/hashmap-util/0.0.1/hashmap-util-0.0.1-sources.jar";
      hash = "sha256-LyplgrKGbavtyt6u9bOLmHa4M0PmpeS+Gm0ge3+Nb6M=";
    }
    {
      name = "reflection-util";
      url = "https://repo.maven.apache.org/maven2/org/plumelib/reflection-util/1.0.6/reflection-util-1.0.6-sources.jar";
      hash = "sha256-eqSSA5EAP7wwcncacc+Oz8vkCK1DJ0XDapE9FVaxw5o=";
    }
  ];
  archives = builtins.map (archive:
    archive
    // {
      src = fetchurl {
        urls = [archive.url];
        inherit (archive) hash;
      };
    })
  sourceArchives;
  archiveArguments = builtins.concatStringsSep " " (builtins.map (archive: "${archive.name} ${archive.src}") archives);

  forkTreeUtils = fetchurl {
    urls = ["https://raw.githubusercontent.com/eisop/checker-framework/${eisopRevision}/javacutil/src/main/java/org/checkerframework/javacutil/TreeUtils.java"];
    hash = "sha256-Gwkp/Izg4JSZZi6TRFlhXLkC0Xy2ZVqbf3biDv8W8s8=";
  };
  forkTreeUtilsAfterJava11 = fetchurl {
    urls = ["https://raw.githubusercontent.com/eisop/checker-framework/${eisopRevision}/javacutil/src/main/java/org/checkerframework/javacutil/TreeUtilsAfterJava11.java"];
    hash = "sha256-6xHc7RR1+YgosMmq/nhTu6BZyzxscBfoa0+QehaeK4Q=";
  };
  checkApiSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/google/errorprone/error_prone_check_api/2.36.0/error_prone_check_api-2.36.0-sources.jar"];
    hash = "sha256-RBTgPTUTPHFp7RuNGCQ/6N9YMxqyq5TT1IUoJGy2yBA=";
  };
  plumeUtilLicense = fetchurl {
    urls = ["https://raw.githubusercontent.com/plume-lib/plume-util/257332c4f88ae1e04edbde8e5c244dd2a53e50c4/LICENSE"];
    hash = "sha256-7Ng28CVA/qVhXfIlt5XtW3FKM1DPa63IAGudH55cxI4=";
  };
  hashmapUtilLicense = fetchurl {
    urls = ["https://raw.githubusercontent.com/plume-lib/hashmap-util/d88d2ba5349474f6c9c7ebb4ea062d900097db5f/LICENSE"];
    hash = "sha256-TdNTNf5hvAVNeAv3XiqA5dEEWjx9gc29/h0u7T/barg=";
  };
  reflectionUtilLicense = fetchurl {
    urls = ["https://raw.githubusercontent.com/plume-lib/reflection-util/53aec91c373f8320c648a17cd3efdc7616010cbd/LICENSE"];
    hash = "sha256-TY0NWoo2hG0a98HoUHDsJpATdAdHmSg0Nff4EmzM9JQ=";
  };
in
  mkDerivation {
    pname = "bazel-error-prone-dataflow";
    inherit version;
    src = (builtins.head archives).src;

    buildDeps = [
      buildJdk
      buildPackages.python3
      buildPackages.findutils
      bazelMavenBootstrap
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          python3 - ${archiveArguments} <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe",
              "4d5a", "504b0304", "504b0506",
          ))

          arguments = sys.argv[1:]
          if len(arguments) != 12:
              raise SystemExit("Expected six pinned Dataflow source archives")

          for name, archive_path in zip(arguments[::2], arguments[1::2]):
              with ZipFile(archive_path) as archive:
                  for member in archive.infolist():
                      path = PurePosixPath(member.filename)
                      kind = stat.S_IFMT(member.external_attr >> 16)
                      if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                          raise SystemExit(f"Unsafe {name} source member: {path}")
                      if member.is_dir():
                          continue

                      data = archive.read(member)
                      if path.suffix.lower() in compiled_suffixes or data.startswith(compiled_signatures):
                          raise SystemExit(f"Compiled {name} source member: {path}")

                      if name == "dataflow-errorprone" and path.suffix == ".java":
                          data = data.replace(
                              b"org.checkerframework.dataflow",
                              b"org.checkerframework.errorprone.dataflow",
                          )
                          data = data.replace(
                              b"org.checkerframework.javacutil",
                              b"org.checkerframework.errorprone.javacutil",
                          )
                          path = PurePosixPath(str(path).replace(
                              "org/checkerframework/dataflow",
                              "org/checkerframework/errorprone/dataflow",
                          ))
                      elif name == "javacutil" and path.suffix == ".java":
                          data = data.replace(
                              b"org.checkerframework.javacutil",
                              b"org.checkerframework.errorprone.javacutil",
                          )
                          path = PurePosixPath(str(path).replace(
                              "org/checkerframework/javacutil",
                              "org/checkerframework/errorprone/javacutil",
                          ))

                      destination = Path("source") / name / str(path)
                      destination.parent.mkdir(parents=True, exist_ok=True)
                      destination.write_bytes(data)

          # The fork shades Dataflow's annotations into the same namespace.
          annotation_root = Path("source/checker-qual/org/checkerframework/dataflow/qual")
          relocated_root = Path("source/relocated-qual/org/checkerframework/errorprone/dataflow/qual")
          relocated_root.mkdir(parents=True)
          for path in annotation_root.glob("*.java"):
              relocated_root.joinpath(path.name).write_bytes(path.read_bytes().replace(
                  b"org.checkerframework.dataflow",
                  b"org.checkerframework.errorprone.dataflow",
              ))

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 606:
              raise SystemExit(f"Expected 606 Dataflow source files, found {len(sources)}")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
          PY

          # The published javacutil sources predate two methods used by this
          # EISOP fork. Use the matching files from its pinned source tag.
          python3 - ${forkTreeUtils} ${forkTreeUtilsAfterJava11} <<'PY'
          from pathlib import Path
          import sys

          javacutil = Path("source/javacutil/org/checkerframework/errorprone/javacutil")
          names = ("TreeUtils.java", "TreeUtilsAfterJava11.java")
          for name, source in zip(names, sys.argv[1:]):
              path = Path(source)
              data = path.read_bytes().replace(
                  b"org.checkerframework.javacutil",
                  b"org.checkerframework.errorprone.javacutil",
              )
              javacutil.joinpath(name).write_bytes(data)
          PY
        '';
      }
      {
        name = "build";
        script = ''
          classpath=$(find ${bazelMavenBootstrap}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          printf '%s\n' "$classpath" > build-classpath

          exports=""
          for package in api code comp file main model parser processing tree util; do
            exports="$exports --add-exports=jdk.compiler/com.sun.tools.javac.$package=ALL-UNNAMED"
          done
          printf '%s\n' "$exports" > module-exports

          mkdir -p classes
          ${buildJdk}/bin/javac -source 17 -target 17 -proc:none -encoding UTF-8 \
            $exports -cp "$classpath" -d classes @java-sources
        '';
      }
      {
        name = "check";
        script = ''
          cat > DataflowSourceSmoke.java <<'JAVA'
          import com.sun.source.tree.SwitchTree;
          import org.checkerframework.errorprone.javacutil.TreeUtils;

          final class DataflowSourceSmoke {
              public static void main(String[] args) throws Exception {
                  TreeUtils.class.getMethod("isEnhancedSwitchStatement", SwitchTree.class);
                  Class.forName("org.checkerframework.errorprone.dataflow.cfg.ControlFlowGraph");
                  Class.forName("org.checkerframework.errorprone.dataflow.qual.Pure");
              }
          }
          JAVA

          classpath="classes:$(cat build-classpath)"
          ${buildJdk}/bin/javac --release 17 -proc:none -cp "$classpath" \
            -d classes DataflowSourceSmoke.java
          ${buildJdk}/bin/java $(cat module-exports) -cp "$classpath" DataflowSourceSmoke
          rm classes/DataflowSourceSmoke.class

          python3 - ${checkApiSource} <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          sources = []
          with ZipFile(sys.argv[1]) as archive:
              for member in archive.infolist():
                  path = PurePosixPath(member.filename)
                  kind = stat.S_IFMT(member.external_attr >> 16)
                  if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                      raise SystemExit(f"Unsafe Error Prone check API source: {path}")
                  if member.is_dir():
                      continue

                  data = archive.read(member)
                  if path.suffix.lower() in {
                      ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
                      ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
                  } or data.startswith(tuple(bytes.fromhex(value) for value in (
                      "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
                      "feedface", "cefaedfe", "feedfacf", "cffaedfe",
                      "4d5a", "504b0304", "504b0506",
                  ))):
                      raise SystemExit(f"Compiled Error Prone check API source: {path}")
                  if path.suffix != ".java":
                      continue

                  destination = Path("check-source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)
                  sources.append(destination)

          if len(sources) != 189:
              raise SystemExit(f"Expected 189 Error Prone check API sources, found {len(sources)}")
          Path("check-sources").write_text("".join(f"{path}\n" for path in sorted(sources)))
          PY

          mkdir -p check-classes
          ${buildJdk}/bin/javac -source 17 -target 17 -proc:none -encoding UTF-8 \
            $(cat module-exports) -cp "$classpath" -d check-classes @check-sources
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/io/github/eisop/dataflow-errorprone/${version}"
          mkdir -p "$destination" "$out/share/licenses/dataflow-errorprone"
          ${buildJdk}/bin/jar --create \
            --file "$destination/dataflow-errorprone-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/dataflow-errorprone/META-INF/LICENSE.txt \
            "$out/share/licenses/dataflow-errorprone/LICENSE"
          cp source/checker-qual/META-INF/LICENSE.txt \
            "$out/share/licenses/dataflow-errorprone/CHECKER-LICENSE"
          cp source/javacutil/META-INF/LICENSE.txt \
            "$out/share/licenses/dataflow-errorprone/JAVACUTIL-LICENSE"
          cp ${plumeUtilLicense} \
            "$out/share/licenses/dataflow-errorprone/PLUME-UTIL-LICENSE"
          cp ${hashmapUtilLicense} \
            "$out/share/licenses/dataflow-errorprone/HASHMAP-UTIL-LICENSE"
          cp ${reflectionUtilLicense} \
            "$out/share/licenses/dataflow-errorprone/REFLECTION-UTIL-LICENSE"

          # Retain the relocated Java sources alongside the GPL and MIT notices.
          cp -R source "$out/share/source"
        '';
      }
    ];
  }
