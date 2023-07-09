{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";

  };


  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: let
      # TODO: only needed when nixpkgs is not up to date.
      odin-overlay = self: super: {
        odin = super.odin.overrideAttrs (old: rec {
          version = "dev-2023-07";
          src = super.fetchFromGitHub {
            owner = "odin-lang";
            repo = "Odin";
            rev = "${version}";
            # How is this determined?
            sha256 = "sha256-qEewo2h4dpivJ7D4RxxBZbtrsiMJ7AgqJcucmanbgxY=";
          };

          nativeBuildInputs = with super; [ makeWrapper which ];

          LLVM_CONFIG = "${super.llvmPackages.llvm.dev}/bin/llvm-config";
          postPatch = ''
            sed -i 's/^GIT_SHA=.*$/GIT_SHA=/' build_odin.sh
            sed -i 's/LLVM-C/LLVM/' build_odin.sh
            patchShebangs build_odin.sh
          '';

          installPhase = old.installPhase + "cp -r vendor $out/bin/vendor";
        });
      };

      pkgs = import nixpkgs {
        inherit system;
        overlays = [
          (odin-overlay)
        ];
      };

      lib = pkgs.lib;
      in {
        devShells.default = pkgs.mkShell {
        nativeBuildInputs = [
        pkgs.odin
        pkgs.ols
        ];
      };
    });
}
