##! Exercises H-through-P Python modules through their documented import APIs.
{testing}: let
  mkPythonModuleProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryProgram,
    badInput,
    badOperation,
    badExpected,
    badProgram,
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
          files."probe.py" = ''
            import glob
            import sys

            locations = glob.glob("@out@/lib/python*/site-packages")
            if len(locations) != 1:
                raise RuntimeError("package does not expose one Python site-packages directory")
            sys.path.insert(0, locations[0])

            ${primaryProgram}
            print("${package} primary passed")
          '';
          steps = [
            {
              argv = ["@python@" "probe.py"];
              exit_code = 0;
              stdout.exact = "${package} primary passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files."probe.py" = ''
            import glob
            import sys

            locations = glob.glob("@out@/lib/python*/site-packages")
            if len(locations) != 1:
                raise RuntimeError("package does not expose one Python site-packages directory")
            sys.path.insert(0, locations[0])

            ${badProgram}
            print("${package} rejected invalid input", file=sys.stderr)
            raise SystemExit(7)
          '';
          steps = [
            {
              argv = ["@python@" "probe.py"];
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
in {
  "python3-lxml" = mkPythonModuleProbe {
    package = "python3-lxml";
    primaryInput = "An XML document containing an integer answer element.";
    primaryOperation = "Parse the bytes and select the element through lxml.etree.";
    primaryExpected = "The selected element contains the text 42.";
    primaryProgram = ''
      from lxml import etree
      root = etree.fromstring(b"<root><answer>42</answer></root>")
      assert root.findtext("answer") == "42"
    '';
    badInput = "An XML document with mismatched tags.";
    badOperation = "Parse the malformed document through lxml.etree.";
    badExpected = "lxml raises XMLSyntaxError and produces no accepted tree.";
    badProgram = ''
      from lxml import etree
      try:
          etree.fromstring(b"<open></closed>")
      except etree.XMLSyntaxError:
          pass
      else:
          raise RuntimeError("lxml accepted malformed XML")
    '';
  };

  "python3-mako" = mkPythonModuleProbe {
    package = "python3-mako";
    primaryInput = "A template adding two supplied integer values.";
    primaryOperation = "Compile and render the template through Mako.";
    primaryExpected = "The rendered output is the exact string answer=42.";
    primaryProgram = ''
      from mako.template import Template
      assert Template("answer=''${left + right}").render(left=19, right=23) == "answer=42"
    '';
    badInput = "A template expression with an unclosed delimiter.";
    badOperation = "Compile the malformed template through Mako.";
    badExpected = "Mako raises its template SyntaxException.";
    badProgram = ''
      from mako import exceptions
      from mako.template import Template
      try:
          Template("answer=''${unclosed")
      except exceptions.SyntaxException:
          pass
      else:
          raise RuntimeError("Mako accepted malformed template syntax")
    '';
  };

  "python3-markdown" = mkPythonModuleProbe {
    package = "python3-markdown";
    primaryInput = "A Markdown heading and emphasized answer.";
    primaryOperation = "Render the source through markdown.markdown.";
    primaryExpected = "The renderer emits the expected h1 and emphasis elements.";
    primaryProgram = ''
      import markdown
      assert markdown.markdown("# Result\n\n*42*") == "<h1>Result</h1>\n<p><em>42</em></p>"
    '';
    badInput = "An extension module name that cannot be imported.";
    badOperation = "Configure the renderer with the nonexistent extension.";
    badExpected = "Markdown rejects configuration by raising ModuleNotFoundError.";
    badProgram = ''
      import markdown
      try:
          markdown.markdown("text", extensions=["qualification_extension_does_not_exist"])
      except ModuleNotFoundError:
          pass
      else:
          raise RuntimeError("Markdown accepted a missing extension")
    '';
  };

  "python3-pygments" = mkPythonModuleProbe {
    package = "python3-pygments";
    primaryInput = "A Python assignment token stream.";
    primaryOperation = "Lex the source with Pygments' Python lexer.";
    primaryExpected = "The tokens include the name answer and integer literal 42.";
    primaryProgram = ''
      from pygments import lex
      from pygments.lexers import PythonLexer
      from pygments.token import Name, Number
      tokens = list(lex("answer = 42\n", PythonLexer()))
      assert (Name, "answer") in tokens
      assert (Number.Integer, "42") in tokens
    '';
    badInput = "A lexer alias that is not registered.";
    badOperation = "Resolve the unknown alias through get_lexer_by_name.";
    badExpected = "Pygments rejects the alias by raising ClassNotFound.";
    badProgram = ''
      from pygments.lexers import get_lexer_by_name
      from pygments.util import ClassNotFound
      try:
          get_lexer_by_name("qualification-lexer-does-not-exist")
      except ClassNotFound:
          pass
      else:
          raise RuntimeError("Pygments accepted an unknown lexer")
    '';
  };

  "python3-pyelftools" = mkPythonModuleProbe {
    package = "python3-pyelftools";
    primaryInput = "The ELF executable produced from a minimal C translation unit.";
    primaryOperation = "Compile the program and parse its ELF header with pyelftools.";
    primaryExpected = "ELFFile recognizes a 32-bit or 64-bit executable container.";
    primaryProgram = ''
      from elftools.elf.elffile import ELFFile
      with open(sys.executable, "rb") as source:
          parsed = ELFFile(source)
          assert parsed.elfclass in (32, 64)
    '';
    badInput = "A plain-text file that lacks the ELF magic and header.";
    badOperation = "Construct ELFFile from the invalid bytes.";
    badExpected = "pyelftools rejects the stream with ELFError.";
    badProgram = ''
      from elftools.common.exceptions import ELFError
      from elftools.elf.elffile import ELFFile
      with open("not-elf", "wb") as destination:
          destination.write(b"not an ELF file")
      try:
          with open("not-elf", "rb") as source:
              ELFFile(source)
      except ELFError:
          pass
      else:
          raise RuntimeError("pyelftools accepted non-ELF bytes")
    '';
  };
}
