##! Bazel Python library repositories backed by AOS source packages.
{
  mkDerivation,
  python3,
  python3-jinja2,
  python3-markupsafe,
}: let
  sitePackages = "lib/python3.14/site-packages";
in
  mkDerivation {
    pname = "workerd-python-repositories";
    version = "${python3-jinja2.version}-${python3-markupsafe.version}";
    buildDeps = [python3];
    runtimeDeps = [python3-jinja2 python3-markupsafe];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/jinja2/site-packages" "$out/markupsafe/site-packages"
          ln -s ${python3-jinja2}/${sitePackages}/jinja2 "$out/jinja2/site-packages/jinja2"
          ln -s ${python3-markupsafe}/${sitePackages}/markupsafe "$out/markupsafe/site-packages/markupsafe"

          cat > "$out/jinja2/BUILD.bazel" <<'BUILD'
          load("@rules_python//python:defs.bzl", "py_library")

          py_library(
              name = "pkg",
              srcs = glob(["site-packages/**/*.py"]),
              data = glob(["site-packages/**/*"], exclude = ["**/*.py", "**/__pycache__/**"]),
              imports = ["site-packages"],
              deps = ["@v8_python_deps//markupsafe:pkg"],
              visibility = ["//visibility:public"],
          )
          BUILD
          cat > "$out/markupsafe/BUILD.bazel" <<'BUILD'
          load("@rules_python//python:defs.bzl", "py_library")

          py_library(
              name = "pkg",
              srcs = glob(["site-packages/**/*.py"]),
              data = glob(["site-packages/**/*"], exclude = ["**/*.py", "**/__pycache__/**"]),
              imports = ["site-packages"],
              visibility = ["//visibility:public"],
          )
          BUILD
          touch "$out/jinja2/REPO.bazel" "$out/markupsafe/REPO.bazel"
        '';
      }
      {
        name = "check";
        script = ''
          PYTHONPATH="$out/jinja2/site-packages:$out/markupsafe/site-packages" \
            ${python3}/bin/python3 - <<'PY'
          from jinja2 import Environment, DictLoader, StrictUndefined
          from markupsafe import _speedups

          environment = Environment(
              loader=DictLoader({"base": "{% block body %}{% endblock %}",
                                 "child": "{% extends 'base' %}{% block body %}{{ value }}{% endblock %}"}),
              autoescape=True,
              undefined=StrictUndefined,
          )
          assert environment.get_template("child").render(value="<service>") == "&lt;service&gt;"
          assert _speedups._escape_inner("<&") == "&lt;&amp;"
          PY
        '';
      }
    ];
    meta = {
      description = "Source-built Jinja2 and MarkupSafe repositories for workerd";
      license = "BSD-3-Clause";
    };
  }
