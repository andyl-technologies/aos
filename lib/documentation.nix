##! lib/documentation.nix - pure constructors for package documentation.
##!
##! These helpers return closed data only. They deliberately do not render
##! Markdown, allocate derivations, inspect the filesystem, or capture store
##! context. The publisher validates their JSON representation against the
##! shared `aos.package-documentation/v1` Rust model before materialization.
let
  asSpans = value:
    if builtins.isString value
    then [
      {
        kind = "text";
        text = value;
      }
    ]
    else value;
in rec {
  text = value: {
    kind = "text";
    text = value;
  };

  inlineCode = value: {
    kind = "code";
    text = value;
  };

  packageLink = package: label: {
    kind = "link";
    inherit label;
    target = {
      kind = "package";
      inherit package;
    };
  };

  optionLink = path: label: {
    kind = "link";
    inherit label;
    target = {
      kind = "option";
      path =
        builtins.map (value: {
          kind = "literal";
          inherit value;
        })
        path;
    };
  };

  sectionLink = id: label: {
    kind = "link";
    inherit label;
    target = {
      kind = "section";
      inherit id;
    };
  };

  sourceLink = path: label: {
    kind = "link";
    inherit label;
    target = {
      kind = "source";
      inherit path;
    };
  };

  httpsLink = url: label: {
    kind = "link";
    inherit label;
    target = {
      kind = "https";
      inherit url;
    };
  };

  paragraph = spans: {
    kind = "paragraph";
    spans = asSpans spans;
  };

  code = language: value: {
    kind = "code";
    inherit language;
    text = value;
  };

  list = {
    ordered ? false,
    items,
  }: {
    kind = "list";
    inherit ordered items;
  };

  note = severity: blocks: {
    kind = "note";
    inherit severity blocks;
  };

  definitions = entries: {
    kind = "definitions";
    inherit entries;
  };

  definition = term: body: {inherit term body;};

  section = title: blocks: {inherit title blocks;};

  activation = kind: units: {inherit kind units;};
}
