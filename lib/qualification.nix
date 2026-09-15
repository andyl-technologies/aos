##! Closed package-owned qualification probe authoring and projection.
{abilities}: let
  limits = abilities.types.limits;
  fail = message: throw "qualification: ${message}";

  requireAttrs = context: required: optional: value: let
    allowed = required ++ optional;
    names =
      if builtins.isAttrs value
      then builtins.attrNames value
      else [];
    missing = builtins.filter (name: !(builtins.hasAttr name value)) required;
    unexpected = builtins.filter (name: !(builtins.elem name allowed)) names;
  in
    if !builtins.isAttrs value
    then fail "${context} must be an attribute set"
    else if missing != []
    then fail "${context} is missing fields: ${builtins.concatStringsSep ", " missing}"
    else if unexpected != []
    then fail "${context} has unsupported fields: ${builtins.concatStringsSep ", " unexpected}"
    else value;

  requireString = context: allowEmpty: value:
    if
      builtins.isString value
      && (allowEmpty || value != "")
      && builtins.stringLength value <= limits.maxStringLength
    then value
    else fail "${context} must be a bounded${if allowEmpty then "" else " nonempty"} string";

  requireRelativePath = context: value:
    if abilities.types.relativePath.check value
    then value
    else fail "${context} must be a normalized relative path";

  requireSelector = context: value:
    if
      builtins.isAttrs value
      && builtins.attrNames value == ["_type" "output" "package"]
      && value._type == "aos-package-output-selector"
    then value
    else fail "${context} must be an exact package-output selector";

  normalizeTemplate = context: value: let
    checked = requireAttrs context ["fragments"] [] value;
    fragments =
      if
        builtins.isList checked.fragments
        && checked.fragments != []
        && builtins.length checked.fragments <= 64
      then builtins.genList (index:
        normalizeFragment "${context}.fragments[${toString index}]" (builtins.elemAt checked.fragments index))
      (builtins.length checked.fragments)
      else fail "${context}.fragments must contain between 1 and 64 fragments";
  in {inherit fragments;};

  normalizeFragment = context: value: let
    kind =
      if builtins.isAttrs value
      then value.kind or null
      else null;
  in
    if kind == "literal"
    then let
      checked = requireAttrs context ["kind" "text"] [] value;
    in {
      inherit (checked) kind;
      text = requireString "${context}.text" true checked.text;
    }
    else if kind == "artifact-path"
    then let
      checked = requireAttrs context ["artifact" "kind" "path"] [] value;
    in {
      inherit (checked) kind;
      artifact = requireSelector "${context}.artifact" checked.artifact;
      path = requireRelativePath "${context}.path" checked.path;
    }
    else if kind == "artifact-root"
    then let
      checked = requireAttrs context ["artifact" "kind"] [] value;
    in {
      inherit (checked) kind;
      artifact = requireSelector "${context}.artifact" checked.artifact;
    }
    else if kind == "work-path"
    then let
      checked = requireAttrs context ["kind" "path"] [] value;
    in {
      inherit (checked) kind;
      path = requireRelativePath "${context}.path" checked.path;
    }
    else if kind == "harness"
    then let
      checked = requireAttrs context ["kind" "tool"] [] value;
    in
      if builtins.elem checked.tool ["bash" "c-compiler" "cxx-compiler" "python"]
      then {inherit (checked) kind tool;}
      else fail "${context}.tool names an unsupported qualification harness"
    else fail "${context}.kind must select literal, artifact-root, artifact-path, work-path, or harness";

  normalizeStep = context: value: let
    checked = requireAttrs context ["argv" "exit_code"] ["observes_rejection" "stderr" "stdin" "stdout" "timeout_seconds"] value;
    argv =
      if builtins.isList checked.argv && checked.argv != [] && builtins.length checked.argv <= 64
      then builtins.genList (index:
        normalizeTemplate "${context}.argv[${toString index}]" (builtins.elemAt checked.argv index))
      (builtins.length checked.argv)
      else fail "${context}.argv must contain between 1 and 64 templates";
    optionalTemplate = field:
      if !(builtins.hasAttr field checked) || checked.${field} == null
      then null
      else normalizeTemplate "${context}.${field}" checked.${field};
    timeout = checked.timeout_seconds or null;
  in
    if !builtins.isInt checked.exit_code || checked.exit_code < 0 || checked.exit_code > 255
    then fail "${context}.exit_code must be an unsigned byte"
    else if timeout != null && (!builtins.isInt timeout || timeout < 1 || timeout > 300)
    then fail "${context}.timeout_seconds must be between 1 and 300"
    else if !builtins.isBool (checked.observes_rejection or false)
    then fail "${context}.observes_rejection must be a boolean"
    else {
      inherit argv;
      stdin = optionalTemplate "stdin";
      stdout = optionalTemplate "stdout";
      stderr = optionalTemplate "stderr";
      inherit (checked) exit_code;
      timeout_seconds = timeout;
      observes_rejection = checked.observes_rejection or false;
    };

  normalizeArtifact = context: value: let
    kind =
      if builtins.isAttrs value
      then value.kind or null
      else null;
  in
    if kind == "text"
    then let
      checked = requireAttrs context ["kind" "path" "text"] [] value;
    in {
      inherit (checked) kind;
      path = requireRelativePath "${context}.path" checked.path;
      text = requireString "${context}.text" true checked.text;
    }
    else if kind == "sha256"
    then let
      checked = requireAttrs context ["digest" "kind" "path"] [] value;
    in
      if !abilities.types.digest.check checked.digest
      then fail "${context}.digest must be a sha256 digest"
      else {
        inherit (checked) kind digest;
        path = requireRelativePath "${context}.path" checked.path;
      }
    else fail "${context}.kind must select text or sha256";

  normalizeOperation = context: value: let
    checked = requireAttrs context ["artifacts" "expected" "files" "input" "operation" "steps"] [] value;
    fileNames =
      if builtins.isAttrs checked.files
      then builtins.attrNames checked.files
      else fail "${context}.files must be an attribute set";
    steps =
      if builtins.isList checked.steps && checked.steps != [] && builtins.length checked.steps <= 16
      then builtins.genList (index:
        normalizeStep "${context}.steps[${toString index}]" (builtins.elemAt checked.steps index))
      (builtins.length checked.steps)
      else fail "${context}.steps must contain between 1 and 16 commands";
    artifacts =
      if builtins.isList checked.artifacts && builtins.length checked.artifacts <= 32
      then builtins.genList (index:
        normalizeArtifact "${context}.artifacts[${toString index}]" (builtins.elemAt checked.artifacts index))
      (builtins.length checked.artifacts)
      else fail "${context}.artifacts must contain at most 32 observations";
  in
    if builtins.length fileNames > 32
    then fail "${context}.files must contain at most 32 inputs"
    else {
      input = requireString "${context}.input" false checked.input;
      operation = requireString "${context}.operation" false checked.operation;
      expected = requireString "${context}.expected" false checked.expected;
      files = builtins.listToAttrs (map (name: {
        name = requireRelativePath "${context}.files key" name;
        value = normalizeTemplate "${context}.files.${name}" checked.files.${name};
      }) fileNames);
      inherit steps artifacts;
    };

  normalizePackageProbe = value: let
    checked = requireAttrs "package probe" ["bad_input" "primary"] [] value;
    primary = normalizeOperation "package probe.primary" checked.primary;
    badInput = normalizeOperation "package probe.bad_input" checked.bad_input;
  in
    if builtins.any (step: step.exit_code != 0) primary.steps
    then fail "package probe.primary must expect successful commands"
    else if !builtins.any (step: step.observes_rejection || step.exit_code != 0) badInput.steps
    then fail "package probe.bad_input must include an observable rejection"
    else {
      inherit primary;
      bad_input = badInput;
    };

  projectTemplate = owner: template: let
    projected = map (fragment:
      if !(builtins.elem fragment.kind ["artifact-path" "artifact-root"])
      then {value = fragment; selectors = [];}
      else let
        normalized = abilities.normalizePackageOutputSelectors {
          inherit owner;
          value = fragment.artifact;
        };
        selector = builtins.removeAttrs normalized ["_type"];
      in {
        value = fragment // {artifact = selector;};
        selectors = [selector];
      }) template.fragments;
  in {
    value.fragments = map (entry: entry.value) projected;
    selectors = builtins.concatMap (entry: entry.selectors) projected;
  };

  projectOperation = owner: operation: let
    projectedFiles = builtins.mapAttrs (_: projectTemplate owner) operation.files;
    projectOptional = value:
      if value == null
      then {value = null; selectors = [];}
      else projectTemplate owner value;
    projectedSteps = map (step: let
      argv = map (projectTemplate owner) step.argv;
      stdin = projectOptional step.stdin;
      stdout = projectOptional step.stdout;
      stderr = projectOptional step.stderr;
    in {
      value = step // {
        argv = map (entry: entry.value) argv;
        stdin = stdin.value;
        stdout = stdout.value;
        stderr = stderr.value;
      };
      selectors =
        builtins.concatMap (entry: entry.selectors) argv
        ++ stdin.selectors
        ++ stdout.selectors
        ++ stderr.selectors;
    }) operation.steps;
  in {
    value = operation // {
      files = builtins.mapAttrs (_: entry: entry.value) projectedFiles;
      steps = map (entry: entry.value) projectedSteps;
    };
    selectors =
      builtins.concatMap (entry: entry.selectors) (builtins.attrValues projectedFiles)
      ++ builtins.concatMap (entry: entry.selectors) projectedSteps;
  };
in rec {
  literal = text: normalizeFragment "literal fragment" {kind = "literal"; inherit text;};
  artifactRoot = {artifact ? abilities.packageOutput {}}:
    normalizeFragment "artifact-root fragment" {kind = "artifact-root"; inherit artifact;};
  artifactPath = {
    artifact ? abilities.packageOutput {},
    path,
  }:
    normalizeFragment "artifact-path fragment" {kind = "artifact-path"; inherit artifact path;};
  workPath = path: normalizeFragment "work-path fragment" {kind = "work-path"; inherit path;};
  harness = tool: normalizeFragment "harness fragment" {kind = "harness"; inherit tool;};
  template = fragments: normalizeTemplate "template" {inherit fragments;};
  text = value: template [(literal value)];
  step = normalizeStep "package probe step";
  operation = normalizeOperation "package probe operation";
  textArtifact = {path, text}: normalizeArtifact "text artifact" {kind = "text"; inherit path text;};
  sha256Artifact = {path, digest}: normalizeArtifact "sha256 artifact" {kind = "sha256"; inherit path digest;};
  packageProbe = {
    primary,
    badInput,
  }:
    normalizePackageProbe {inherit primary; bad_input = badInput;};

  commandProbe = {primary, badInput}: let
    tokenPattern = "(@out@/[A-Za-z0-9._+/-]*[A-Za-z0-9._+-]|@output:[A-Za-z0-9._+-]+@/[A-Za-z0-9._+/-]*[A-Za-z0-9._+-]|@work@/[A-Za-z0-9._+/-]*[A-Za-z0-9._+-]|@python@|@bash@|@cc@|@cxx@|@out@)";
    harnesses = {
      "@bash@" = "bash";
      "@cc@" = "c-compiler";
      "@cxx@" = "cxx-compiler";
      "@python@" = "python";
    };
    fragmentFor = value:
      if builtins.isList value
      then fragmentFor (builtins.head value)
      else if builtins.hasAttr value harnesses
      then harness harnesses.${value}
      else if value == "@out@"
      then artifactRoot {}
      else let
        namedOutput = builtins.match "@output:([A-Za-z0-9._+-]+)@/(.+)" value;
        outputPath = builtins.match "@out@/(.+)" value;
        work = builtins.match "@work@/(.+)" value;
      in
        if namedOutput != null
        then artifactPath {
          artifact = abilities.packageOutput {output = builtins.elemAt namedOutput 0;};
          path = builtins.elemAt namedOutput 1;
        }
        else if outputPath != null
        then artifactPath {path = builtins.head outputPath;}
        else if work != null
        then workPath (builtins.head work)
        else literal value;
    stringTemplate = value:
      if value == ""
      then text ""
      else template (map fragmentFor (builtins.filter (part: part != "") (builtins.split tokenPattern value)));
    optionalExact = step: field:
      if !(builtins.hasAttr field step)
      then null
      else stringTemplate step.${field}.exact;
    commandStep = step:
      normalizeStep "command probe step" {
        argv = map stringTemplate step.argv;
        stdin =
          if step ? stdin
          then stringTemplate step.stdin
          else null;
        stdout = optionalExact step "stdout";
        stderr = optionalExact step "stderr";
        inherit (step) exit_code;
        timeout_seconds = step.timeout_seconds or null;
        observes_rejection = step.observes_rejection or false;
      };
    commandOperation = operation:
      normalizeOperation "command probe operation" {
        inherit (operation) input operation expected;
        files = builtins.mapAttrs (_: stringTemplate) operation.files;
        steps = map commandStep operation.steps;
        artifacts = map textArtifact operation.artifacts;
      };
  in
    packageProbe {
      primary = commandOperation primary;
      badInput = commandOperation badInput;
    };

  providerExecutableProbe = {
    name,
    entryPoint,
  }:
    commandProbe {
      primary = {
        input = "The installed provider executable.";
        operation = "Verify the package publishes its declared executable entry point.";
        expected = "The entry point is a regular executable file.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              "import os\npath = '@out@/${entryPoint}'\nassert os.path.isfile(path) and os.access(path, os.X_OK)\nprint('${name} executable passed')\n"
            ];
            exit_code = 0;
            stdout.exact = "${name} executable passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "An unsupported qualification argument.";
        operation = "Invoke the provider with an unsupported argument.";
        expected = "The provider rejects the unsupported invocation.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run(['@out@/${entryPoint}', '--aos-qualification-invalid'], capture_output=True)\nassert result.returncode != 0\nsys.stderr.write('${name} rejected invalid input\\n')\nraise SystemExit(7)\n"
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "${name} rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };

  inherit normalizePackageProbe;

  projectPackageProbe = {
    owner,
    probe,
  }: let
    normalized = normalizePackageProbe probe;
    primary = projectOperation owner normalized.primary;
    badInput = projectOperation owner normalized.bad_input;
  in {
    value = {
      primary = primary.value;
      bad_input = badInput.value;
    };
    selectors = abilities.canonicalizePackageOutputSelectors (primary.selectors ++ badInput.selectors);
  };
}
