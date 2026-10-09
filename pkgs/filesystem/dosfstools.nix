##! dosfstools — Utilities for making and checking FAT filesystems
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
}: let
  version = "4.2";
  upstream = mkGithubUpstream {
    unitId = "dosfstools-4";
    family = "dosfstools";
    stream = "4";
    owner = "pkgs/filesystem/dosfstools.nix";
    inherit version;
    upstreamId = "v4.2";
    repository = "dosfstools/dosfstools";
    provider = "github-releases";
    tagPrefix = "v";
    major = 4;
    versionScheme = "numeric";
    source = {
      authority = "github.com";
      path = [
        "dosfstools"
        "dosfstools"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "dosfstools-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-ZJJu6/kAktyiGxQlmlMBt7mOexlD6KIBx9cmCEgJtSc=";
    };
  };
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "dosfstools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Both filesystem construction and consistency checking succeed.";
        "files" = {};
        "input" = "A request for a sparse 1 MiB FAT filesystem image.";
        "operation" = "Create the image with mkfs.fat and validate it read-only with fsck.fat.";
        "steps" = [
          {
            "argv" = [
              "@out@/sbin/mkfs.fat"
              "-C"
              "filesystem.img"
              "1024"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/sbin/fsck.fat"
              "-n"
              "filesystem.img"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Mkfs.fat rejects the size with status 1.";
        "files" = {};
        "input" = "A request for a one-block image, below the minimum FAT filesystem size.";
        "operation" = "Attempt to construct the undersized filesystem.";
        "steps" = [
          {
            "argv" = [
              "@out@/sbin/mkfs.fat"
              "-C"
              "undersized.img"
              "1"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit (upstream) version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    patches =
      if stdenv.hostPlatform.isDarwin
      then [./dosfstools-patches/0001-limit-sysmacros-to-linux.patch]
      else [];

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dosfstools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-compat-symlinks
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
          # Keep the FAT alias as a regular executable for image finalization.
          rm "$out/sbin/mkfs.vfat"
          cp "$out/sbin/mkfs.fat" "$out/sbin/mkfs.vfat"
        '';
      }
    ];

    meta = {
      description = "Utilities for making and checking FAT filesystems";
      homepage = "https://github.com/dosfstools/dosfstools";
      license = "GPL-3.0-or-later";
    };
  }
