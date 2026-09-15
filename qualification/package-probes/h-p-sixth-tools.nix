##! Exercises a sixth H-through-P command slice through deterministic offline paths.
{testing}: let
  mkCommandProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryCommand,
    primaryCheck,
    badInput,
    badOperation,
    badExpected,
    badCommand,
    badCheck ? "result.returncode != 0",
    primaryFiles ? {},
    badFiles ? {},
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
          files = primaryFiles;
          steps = [
            {
              argv = [
                "@python@"
                "-c"
                ''
                  import subprocess
                  result = subprocess.run(${primaryCommand}, capture_output=True, text=True)
                  assert ${primaryCheck}, (result.returncode, result.stdout, result.stderr)
                  print("${package} operation passed")
                ''
              ];
              exit_code = 0;
              stdout.exact = "${package} operation passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = [
            {
              argv = [
                "@python@"
                "-c"
                ''
                  import subprocess, sys
                  result = subprocess.run(${badCommand}, capture_output=True, text=True)
                  assert ${badCheck}, (result.returncode, result.stdout, result.stderr)
                  sys.stderr.write("${package} rejected invalid input\n")
                  raise SystemExit(7)
                ''
              ];
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

  mkHelpProbe = {
    package,
    executable ? package,
    directory ? "bin",
    helpArgument ? "--help",
    helpNeedle ? "usage",
    badArgument ? "--aos-invalid-option",
  }:
    mkCommandProbe {
      inherit package;
      primaryInput = "The packaged ${package} command-line interface.";
      primaryOperation = "Request its offline help text.";
      primaryExpected = "The command returns success and documents its invocation contract.";
      primaryCommand = ''["@out@/${directory}/${executable}", "${helpArgument}"]'';
      primaryCheck = ''result.returncode == 0 and ${builtins.toJSON helpNeedle} in (result.stdout + result.stderr).lower()'';
      badInput = "A ${package} invocation containing an unsupported option.";
      badOperation = "Parse the invalid option without accessing a device or service.";
      badExpected = "The command rejects the unsupported option before performing external I/O.";
      badCommand = ''["@out@/${directory}/${executable}", "${badArgument}"]'';
    };
in {
  hdparm = mkHelpProbe {
    package = "hdparm";
    directory = "sbin";
    helpArgument = "--help";
    helpNeedle = "usage";
  };

  htop = mkCommandProbe {
    package = "htop";
    primaryInput = "The packaged interactive process viewer's option inventory.";
    primaryOperation = "Request help without opening the interactive display.";
    primaryExpected = "Htop describes its delay, filter, sort, and tree options.";
    primaryCommand = ''["@out@/bin/htop", "--help"]'';
    primaryCheck = ''result.returncode == 0 and "--sort-key" in result.stdout and "--filter" in result.stdout'';
    badInput = "A sort request naming a field that does not exist.";
    badOperation = "Validate the sort field before opening the display.";
    badExpected = "Htop rejects the unknown sort field.";
    badCommand = ''["@out@/bin/htop", "--sort-key=AOS_INVALID_FIELD"]'';
  };

  hubble = mkCommandProbe {
    package = "hubble";
    primaryInput = "A request for Hubble's Bash completion program.";
    primaryOperation = "Generate the completion program without contacting Hubble Relay.";
    primaryExpected = "Hubble returns a Bash function wired to its completion endpoint.";
    primaryCommand = ''["@out@/bin/hubble", "completion", "bash"]'';
    primaryCheck = ''result.returncode == 0 and "__start_hubble" in result.stdout and "complete -o default" in result.stdout'';
    badInput = "A Hubble invocation naming an unknown top-level command.";
    badOperation = "Parse the unsupported command without contacting Hubble Relay.";
    badExpected = "Hubble rejects the unknown command.";
    badCommand = ''["@out@/bin/hubble", "aos-invalid-command"]'';
  };

  inetutils = mkCommandProbe {
    package = "inetutils";
    primaryInput = "One ICMP echo request addressed to the IPv4 loopback interface.";
    primaryOperation = "Send and receive the request through GNU ping.";
    primaryExpected = "Ping reports one transmitted and one received packet.";
    primaryCommand = ''["@out@/bin/ping", "-c", "1", "127.0.0.1"]'';
    primaryCheck = ''result.returncode == 0 and "1 packets transmitted" in result.stdout and "1 packets received" in result.stdout'';
    badInput = "A ping invocation containing an unsupported option.";
    badOperation = "Parse the invalid option without resolving or contacting a host.";
    badExpected = "Ping rejects the unsupported option.";
    badCommand = ''["@out@/bin/ping", "--aos-invalid-option"]'';
  };

  ipmitool = mkHelpProbe {
    package = "ipmitool";
    executable = "ipmitool";
    helpArgument = "-h";
    helpNeedle = "interfaces";
  };

  iproute2 = mkCommandProbe {
    package = "iproute2";
    primaryInput = "A socket query filtered by both source port 1 and destination port 2.";
    primaryOperation = "Parse and execute the filter through ss without printing headers.";
    primaryExpected = "Ss accepts the compound port filter and completes the local socket query.";
    primaryCommand = ''["@out@/sbin/ss", "-H", "sport = :1 and dport = :2"]'';
    primaryCheck = "result.returncode == 0";
    badInput = "A socket filter containing an invalid address prefix.";
    badOperation = "Parse the malformed destination predicate.";
    badExpected = "Ss rejects the malformed address predicate.";
    badCommand = ''["@out@/sbin/ss", "-H", "dst", "qualification"]'';
    badCheck = ''result.returncode != 0 and "cannot parse" in result.stderr.lower()'';
  };

  ipset = mkCommandProbe {
    package = "ipset";
    primaryInput = "The built-in help request for the hash:ip set type.";
    primaryOperation = "Translate the request and inspect its type-specific grammar offline.";
    primaryExpected = "IpSet documents IPv4 and IPv6 hash entries and their create options.";
    primaryCommand = ''["@out@/sbin/ipset-translate", "help", "hash:ip"]'';
    primaryCheck = ''result.returncode == 0 and "hash:ip type specific options" in result.stdout and "family inet|inet6" in result.stdout'';
    badInput = "A help request naming an unknown set type.";
    badOperation = "Resolve the nonexistent set type through the translator.";
    badExpected = "IpSet rejects the unknown type without contacting the kernel.";
    badCommand = ''["@out@/sbin/ipset-translate", "help", "unknown:type"]'';
    badCheck = ''result.returncode != 0 and "unknown" in result.stderr.lower()'';
  };

  kubelet = mkCommandProbe {
    package = "kubelet";
    primaryInput = "A request for Kubelet's Bash completion program.";
    primaryOperation = "Generate the completion program without starting the node agent.";
    primaryExpected = "Kubelet returns a Bash function wired to its completion endpoint.";
    primaryCommand = ''["@out@/bin/kubelet", "completion", "bash"]'';
    primaryCheck = ''result.returncode == 0 and "__start_kubelet" in result.stdout and "complete -o default" in result.stdout'';
    badInput = "A Kubelet invocation naming an unknown top-level command.";
    badOperation = "Parse the unsupported command without starting the node agent.";
    badExpected = "Kubelet rejects the unknown command.";
    badCommand = ''["@out@/bin/kubelet", "aos-invalid-command"]'';
  };

  libgcrypt = mkCommandProbe {
    package = "libgcrypt";
    primaryInput = "The byte string abc and the HMAC key key.";
    primaryOperation = "Compute its HMAC-SHA-256 through the packaged helper.";
    primaryExpected = "The helper returns the known 256-bit authentication code.";
    primaryCommand = ''["@out@/bin/hmac256", "key", "message.txt"]'';
    primaryCheck = ''result.returncode == 0 and result.stdout == "9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab  message.txt\n"'';
    primaryFiles."message.txt" = "abc";
    badInput = "An HMAC request with no key argument.";
    badOperation = "Validate the incomplete helper invocation.";
    badExpected = "The helper rejects the missing key and prints its usage contract.";
    badCommand = ''["@out@/bin/hmac256"]'';
    badCheck = ''result.returncode != 0 and "usage:" in result.stderr.lower()'';
  };

  nerdctl = mkCommandProbe {
    package = "nerdctl";
    primaryInput = "A request for nerdctl's Bash completion program.";
    primaryOperation = "Generate the completion program without contacting containerd.";
    primaryExpected = "Nerdctl returns a Bash function wired to its completion endpoint.";
    primaryCommand = ''["@out@/bin/nerdctl", "completion", "bash"]'';
    primaryCheck = ''result.returncode == 0 and "__start_nerdctl" in result.stdout and "complete -o default" in result.stdout'';
    badInput = "A nerdctl invocation naming an unknown top-level command.";
    badOperation = "Parse the unsupported command without contacting containerd.";
    badExpected = "Nerdctl rejects the unknown command.";
    badCommand = ''["@out@/bin/nerdctl", "aos-invalid-command"]'';
  };

  nftables = mkCommandProbe {
    package = "nftables";
    primaryInput = "An nftables source file defining the integer symbol qualification.";
    primaryOperation = "Parse the definition in check-only mode.";
    primaryExpected = "Nft accepts the offline definition without modifying a ruleset.";
    primaryCommand = ''["@out@/sbin/nft", "--check", "--file", "definition.nft"]'';
    primaryCheck = "result.returncode == 0";
    primaryFiles."definition.nft" = "define qualification = 42\n";
    badInput = "An nftables definition with no expression after the equals sign.";
    badOperation = "Parse the malformed definition in check-only mode.";
    badExpected = "Nft rejects the incomplete definition.";
    badCommand = ''["@out@/sbin/nft", "--check", "--file", "invalid.nft"]'';
    badCheck = ''result.returncode != 0 and "syntax error" in result.stderr.lower()'';
    badFiles."invalid.nft" = "define qualification =\n";
  };

  opkssh = mkHelpProbe {
    package = "opkssh";
    helpNeedle = "usage";
    badArgument = "aos-invalid-command";
  };

  passt = mkHelpProbe {
    package = "passt";
    executable = "passt";
    helpNeedle = "usage";
  };

  polkit = mkCommandProbe {
    package = "polkit";
    primaryInput = "The pkaction command's compiled release identity.";
    primaryOperation = "Request the version without contacting the authorization daemon.";
    primaryExpected = "Pkaction reports Polkit version 127.";
    primaryCommand = ''["@out@/bin/pkaction", "--version"]'';
    primaryCheck = ''result.returncode == 0 and "127" in (result.stdout + result.stderr)'';
    badInput = "A pkaction invocation containing an unsupported option.";
    badOperation = "Parse the invalid option without contacting the authorization daemon.";
    badExpected = "Pkaction rejects the unsupported option.";
    badCommand = ''["@out@/bin/pkaction", "--aos-invalid-option"]'';
  };
}
