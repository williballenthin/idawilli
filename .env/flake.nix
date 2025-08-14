{
  description = "virtual environments";

  inputs = {

    nixpkgs = {
      type = "github";
      owner = "nixos";
      repo = "nixpkgs";
      # nixos-25.05
      ref = "b43c397f6c213918d6cfe6e3550abfe79b5d1c51";
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
