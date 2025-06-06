{
  description = "virtual environments";

  inputs = {

    nixpkgs = {
      type = "github";
      owner = "nixos";
      repo = "nixpkgs";
      # nixos-24.11
      ref = "314e12ba369ccdb9b352a4db26ff419f7c49fa84";
    };
    devshell = {
      url = "github:numtide/devshell";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
  };

  outputs = { self, flake-utils, devshell, nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system: {
      devShell =
        let
        pkgs = import nixpkgs {
          inherit system;

          overlays = [ devshell.overlays.default ];
        };
        in
        pkgs.devshell.mkShell {
          imports = [ (pkgs.devshell.importTOML ./devshell.toml) ];
          env = [
            {
              name = "LD_LIBRARY_PATH";
              value = "${
                nixpkgs.lib.makeLibraryPath
                # extend library path here
                (with pkgs; [ stdenv.cc.cc openssl ])
              }:$LD_LIBRARY_PATH";
            }
          ];
        };
    });
}
