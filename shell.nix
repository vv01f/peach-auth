{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    (pkgs.python3.withPackages (ps: [
      ps.secp256k1
      ps.coincurve
    ]))

    pkgs.python3Packages.bech32
    pkgs.python3Packages.requests
    pkgs.jq
    pkgs.curl
    pkgs.python313Packages.bip-utils # for shorter python implementation
  ];

  shellHook = ''
      export NIXPKGS_ALLOW_INSECURE=1
    '';
}
