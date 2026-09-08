##! Exercises a fourth H-through-P command slice with local deterministic inputs.
{testing}: let
  mkCommandProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryFiles ? {},
    primarySteps,
    primaryArtifacts ? [],
    badInput,
    badOperation,
    badExpected,
    badFiles ? {},
    badSteps,
    badArtifacts ? [],
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
          steps = primarySteps;
          artifacts = primaryArtifacts;
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = badSteps;
          artifacts = badArtifacts;
        };
      };
    };
in {
  iptables = mkCommandProbe {
    package = "iptables";
    primaryInput = "An INPUT rule accepting TCP traffic to destination port 80.";
    primaryOperation = "Translate the legacy rule into nftables syntax.";
    primaryExpected = "Iptables emits the equivalent nft add-rule command.";
    primarySteps = [
      {
        argv = ["@out@/bin/iptables-translate" "-A" "INPUT" "-p" "tcp" "--dport" "80" "-j" "ACCEPT"];
        exit_code = 0;
        stdout.exact = "nft 'add rule ip filter INPUT tcp dport 80 counter accept'\n";
        stderr.exact = "";
      }
    ];
    badInput = "An INPUT rule naming a protocol that does not exist.";
    badOperation = "Translate the malformed rule through iptables-translate.";
    badExpected = "Iptables rejects the unknown protocol with status 2.";
    badSteps = [
      {
        argv = ["@out@/bin/iptables-translate" "-A" "INPUT" "-p" "qualification-invalid" "-j" "ACCEPT"];
        exit_code = 2;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  libburn = mkCommandProbe {
    package = "libburn";
    primaryInput = "A ten-byte data track containing answer=42.";
    primaryOperation = "Burn the track into an emulated stdio device through cdrskin.";
    primaryExpected = "Cdrskin creates one padded track whose payload and zero-filled remainder are exact.";
    primaryFiles."answer.txt" = "answer=42\n";
    primarySteps = [
      {
        argv = ["@out@/bin/cdrskin" "--allow_emulated_drives" "dev=stdio:track.img" "-data" "answer.txt"];
        exit_code = 0;
      }
      {
        argv = ["@python@" "-c" "data=open('track.img','rb').read(); assert len(data)==2048 and data[:10]==b'answer=42\\n' and not any(data[10:])"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      }
    ];
    badInput = "A data-track pathname that does not exist.";
    badOperation = "Attach the missing track to an emulated stdio device through cdrskin.";
    badExpected = "Cdrskin rejects the missing source with status 3.";
    badSteps = [
      {
        argv = ["@out@/bin/cdrskin" "--allow_emulated_drives" "dev=stdio:track.img" "-data" "missing.txt"];
        exit_code = 3;
        observes_rejection = true;
      }
    ];
  };

  libisoburn = mkCommandProbe {
    package = "libisoburn";
    primaryInput = "A file containing answer=42 for the root of an ISO image.";
    primaryOperation = "Create the ISO with xorriso, extract the file, and compare its exact contents.";
    primaryExpected = "Xorriso round-trips the file through its ISO filesystem implementation.";
    primaryFiles."answer.txt" = "answer=42\n";
    primarySteps = [
      {
        argv = ["@out@/bin/xorriso" "-report_about" "SORRY" "-outdev" "image.iso" "-map" "answer.txt" "/answer.txt" "-commit"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "xorriso 1.5.8.pl02 : RockRidge filesystem manipulator, libburnia project.\n\n";
      }
      {
        argv = ["@out@/bin/xorriso" "-report_about" "SORRY" "-osirrox" "on" "-indev" "image.iso" "-extract" "/answer.txt" "extracted.txt"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "xorriso 1.5.8.pl02 : RockRidge filesystem manipulator, libburnia project.\n\n";
      }
    ];
    primaryArtifacts = [
      {
        path = "extracted.txt";
        text = "answer=42\n";
      }
    ];
    badInput = "An xorriso command name that does not exist.";
    badOperation = "Parse the unsupported command through xorriso's dispatcher.";
    badExpected = "Xorriso rejects the command with status 5.";
    badSteps = [
      {
        argv = ["@out@/bin/xorriso" "-report_about" "SORRY" "-qualification-invalid"];
        exit_code = 5;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };

  pciutils = mkCommandProbe {
    package = "pciutils";
    primaryInput = "A PCI configuration dump for an Intel 8086:1237 host bridge.";
    primaryOperation = "Parse the dump and render its numeric identity through lspci.";
    primaryExpected = "Lspci reports the exact bus address, class, device ID, and revision.";
    primaryFiles."pci.dump" = ''
      00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
      00: 86 80 37 12 06 00 00 00 02 00 00 06 00 00 00 00
    '';
    primarySteps = [
      {
        argv = ["@out@/bin/lspci" "-F" "pci.dump" "-n"];
        exit_code = 0;
        stdout.exact = "00:00.0 0600: 8086:1237 (rev 02)\n";
        stderr.exact = "";
      }
    ];
    badInput = "A PCI dump containing an unterminated record.";
    badOperation = "Parse the malformed dump through lspci.";
    badExpected = "Lspci rejects the dump with status 1.";
    badFiles."pci.dump" = "unterminated";
    badSteps = [
      {
        argv = ["@out@/bin/lspci" "-F" "pci.dump" "-n"];
        exit_code = 1;
        stdout.exact = "";
        observes_rejection = true;
      }
    ];
  };
}
