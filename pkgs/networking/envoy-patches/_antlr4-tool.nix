##! Native ANTLR 4 tool for Envoy's CEL grammar, assembled from Java sources.
{
  mkDerivation,
  fetchurl,
  buildJdk,
  buildPython,
  icu4j,
}: let
  version = "4.13.1";

  antlr3Source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/antlr/antlr-runtime/3.5.3/antlr-runtime-3.5.3-sources.jar"];
    hash = "sha256-tDU6pScNXd7bxZ3m/HuxcMbY+mKT03UzowQUShjksk0=";
  };
  stringTemplateSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/antlr/ST4/4.3.4/ST4-4.3.4-sources.jar"];
    hash = "sha256-ZJBPWl9FHAaRq70gq6jXA98R+aBKtOcCuNDqENPPMfw=";
  };
  treeLayoutSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/abego/treelayout/org.abego.treelayout.core/1.0.3/org.abego.treelayout.core-1.0.3-sources.jar"];
    hash = "sha256-K4cDfoplD0GyQlv2nkzDDMhCwGFerBuhyiFB3VRLHdY=";
  };
  antlr4RuntimeSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/antlr/antlr4-runtime/${version}/antlr4-runtime-${version}-sources.jar"];
    hash = "sha256-AjnvZ7x3XmVLL0R/OBnTNm+yRd38YjuLb9U0kHRy0Xg=";
  };
  antlr4ToolSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/antlr/antlr4/${version}/antlr4-${version}-sources.jar"];
    hash = "sha256-ZlLHqKAlpII48K7h+HIaqKbBSE1XL+AvqTal5xf+Ym0=";
  };
in
  mkDerivation {
    pname = "envoy-antlr4-tool";
    inherit version;
    src = antlr4ToolSource;

    buildDeps = [buildJdk buildPython icu4j];
    runtimeDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          ${buildPython}/bin/python3 ${./_build-antlr4-tool.py} \
            --out "$out" \
            --javac ${buildJdk}/bin/javac \
            --jar ${buildJdk}/bin/jar \
            --icu-jar ${icu4j}/share/java/icu4j-${icu4j.version}.jar \
            --antlr3 ${antlr3Source} \
            --stringtemplate ${stringTemplateSource} \
            --treelayout ${treeLayoutSource} \
            --antlr4-runtime ${antlr4RuntimeSource} \
            --antlr4-tool ${antlr4ToolSource}
        '';
      }
    ];

    passthru.evidenceSources = [
      antlr3Source
      stringTemplateSource
      treeLayoutSource
      antlr4RuntimeSource
      antlr4ToolSource
    ];
  }
