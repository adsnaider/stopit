{
  description = "stopit: a Linux sandbox tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        stopit-bin = pkgs.rustPlatform.buildRustPackage {
          pname = "stopit";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;
          nativeBuildInputs = [
            pkgs.bubblewrap
            pkgs.makeWrapper
          ];
          # bwrap for every sandbox, and pasta for `network = "full"`.
          postInstall = ''
            wrapProgram $out/bin/stopit \
              --prefix PATH : ${pkgs.lib.makeBinPath [pkgs.bubblewrap pkgs.passt]}
          '';
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            bubblewrap
            passt
            jujutsu
            git
          ];
        };
        packages = rec {
          stopit = stopit-bin;
          default = stopit;
        };
      }
    )
    // {
      homeModules.default = {
        config,
        lib,
        pkgs,
        ...
      }: let
        tomlFormat = pkgs.formats.toml {};
        settings = lib.recursiveUpdate config.stopit.config config.programs.stopit.config;
      in {
        options = {
          programs.stopit.config = lib.mkOption {
            type = tomlFormat.type;
            default = {};
            description = "Configuration written to ~/.config/stopit/config.toml";
          };
          stopit.config = lib.mkOption {
            type = tomlFormat.type;
            default = {};
            description = "Alias for programs.stopit.config";
          };
        };

        config = lib.mkMerge [
          {
            home.packages = [
              self.packages.${pkgs.system}.stopit
            ];
          }
          (lib.mkIf (settings != {}) {
            xdg.configFile."stopit/config.toml".source =
              tomlFormat.generate "stopit-config.toml" settings;
          })
          (lib.mkIf (config ? skills) {
            skills = {
              stopit-sandbox = "${self}/skills/stopit-sandbox";
            };
          })
        ];
      };
    };
}
