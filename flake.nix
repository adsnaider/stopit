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
          postInstall = ''
            wrapProgram $out/bin/stopit \
              --prefix PATH : ${pkgs.lib.makeBinPath [pkgs.bubblewrap]}
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
      homeModules.default = {pkgs, ...}: {
        home.packages = [
          self.packages.${pkgs.system}.stopit
        ];
      };
    };
}
