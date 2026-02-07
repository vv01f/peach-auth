{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    (pkgs.python3.withPackages (ps: [
      ps.secp256k1
      ps.coincurve
    ]))

    pkgs.jq
    pkgs.curl
    pkgs.python3Packages.bech32
    pkgs.python3Packages.requests
    pkgs.python3Packages.gnureadline # tab completion
    pkgs.python313Packages.bip-utils # for shorter python implementation
  ];

  shellHook = ''
      export NIXPKGS_ALLOW_INSECURE=1
    '';
}
