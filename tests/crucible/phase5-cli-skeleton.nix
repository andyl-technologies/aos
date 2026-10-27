{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliSkeleton",
  taskIds ? ["T-CLI-1"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  cliMain = import ./_cli-source.nix {inherit lib;};
  cliManifest = builtins.readFile ../../crates/crucible/crucible-cli/Cargo.toml;
  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-1 completion note";
        needle = "Completed by `checks.crucible.phase5.cliSkeleton`";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "clap dependency";
        needle = "clap = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-cli/src/main.rs" cliMain [
      {
        label = "derive parser";
        needle = "#[derive(Parser";
      }
      {
        label = "derive subcommand";
        needle = "#[derive(Subcommand";
      }
      {
        label = "derive args";
        needle = "#[derive(Args";
      }
      {
        label = "seed env";
        needle = "CRUCIBLE_SEED_ENV: &str = \"CRUCIBLE_SEED\"";
      }
      {
        label = "backend enum";
        needle = "enum Backend";
      }
      {
        label = "output format enum";
        needle = "enum OutputFormat";
      }
      {
        label = "global artifact dir";
        needle = "artifact_dir: PathBuf";
      }
      {
        label = "closed run subcommand";
        needle = "Run(RunArgs)";
      }
      {
        label = "closed verify subcommand";
        needle = "Verify(VerifyArgs)";
      }
      {
        label = "closed selftest subcommand";
        needle = "Selftest(SelftestArgs)";
      }
      {
        label = "closed save subcommand";
        needle = "Save(SaveArgs)";
      }
      {
        label = "closed resume subcommand";
        needle = "Resume(ResumeArgs)";
      }
      {
        label = "closed replay subcommand";
        needle = "Replay(ReplayArgs)";
      }
      {
        label = "closed search subcommand";
        needle = "Search(SearchArgs)";
      }
      {
        label = "closed fuzz subcommand";
        needle = "Fuzz(FuzzArgs)";
      }
      {
        label = "closed triage subcommand";
        needle = "Triage(CampaignTriageRouteArgs)";
      }
      {
        label = "closed debug subcommand";
        needle = "Debug(DebugArgs)";
      }
      {
        label = "closed serve subcommand";
        needle = "Serve(ServeArgs)";
      }
      {
        label = "closed completions subcommand";
        needle = "Completions(CompletionsArgs)";
      }
      {
        label = "closed subcommand test";
        needle = "cli_skeleton_exposes_closed_subcommand_set";
      }
      {
        label = "global flag parser test";
        needle = "cli_skeleton_parses_global_flag_block";
      }
      {
        label = "unknown subcommand rejection test";
        needle = "cli_skeleton_rejects_unknown_subcommands";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI skeleton check";
        needle = "cliSkeleton = import ./phase5-cli-skeleton.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 CLI skeleton check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase5-cli-skeleton";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-cli-skeleton";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-cli \
              cli_skeleton \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            component=crucible-cli
            parser=clap-derive
            subcommands=run,verify,selftest,save,resume,replay,search,fuzz,triage,debug,serve,campaign,store,completions
            globals=seed,backend,daemon,qemu,plugin,store,format,trace,artifact-dir,verbose,quiet
            RESULT
          '';
        }
      ];
    }
