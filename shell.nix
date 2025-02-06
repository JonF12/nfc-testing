{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  shellHook = ''
    export LD_LIBRARY_PATH=$NIX_LD_LIBRARY_PATH
  '';
}
