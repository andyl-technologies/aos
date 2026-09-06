##! dosfstools — Utilities for making and checking FAT filesystems
{
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
    pname = "dosfstools";
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
        '';
      }
    ];

    meta = {
      description = "Utilities for making and checking FAT filesystems";
      homepage = "https://github.com/dosfstools/dosfstools";
      license = "GPL-3.0-or-later";
    };
  }
