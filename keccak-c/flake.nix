{
  description = "Keccak/SHA-3 implementation in C";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = {
          default = pkgs.stdenv.mkDerivation {
            pname = "keccak";
            version = "0.1.0";

            src = ./.;

            buildInputs = [ ];
            nativeBuildInputs = [ pkgs.gcc ];

            buildPhase = ''
              # Compile the library
              gcc -c -O3 -Wall -Wextra -std=c99 -o keccak.o keccak.c
              
              # Create static library
              ar rcs libkeccak.a keccak.o
              
              # Compile the test program
              gcc -O3 -Wall -Wextra -std=c99 -o test test.c keccak.o
              
              # Compile the CLI program
              gcc -O3 -Wall -Wextra -std=c99 -o keccak-cli keccak-cli.c keccak.o
            '';

            checkPhase = ''
              echo "Running tests..."
              ./test
            '';

            doCheck = true;

            installPhase = ''
              mkdir -p $out/bin
              mkdir -p $out/lib
              mkdir -p $out/include
              
              cp test $out/bin/keccak-test
              cp keccak-cli $out/bin/keccak
              cp libkeccak.a $out/lib/
              cp keccak.h $out/include/
            '';

            meta = with pkgs.lib; {
              description = "Keccak/SHA-3 cryptographic hash implementation in C";
              license = licenses.mit;
              platforms = platforms.all;
            };
          };

          test = pkgs.stdenv.mkDerivation {
            pname = "keccak-test";
            version = "0.1.0";

            src = ./.;

            buildInputs = [ ];
            nativeBuildInputs = [ pkgs.gcc ];

            buildPhase = ''
              gcc -c -O3 -Wall -Wextra -std=c99 -o keccak.o keccak.c
              gcc -O3 -Wall -Wextra -std=c99 -o test test.c keccak.o
            '';

            installPhase = ''
              mkdir -p $out/bin
              cp test $out/bin/keccak-test
            '';

            doCheck = true;
            checkPhase = ''
              ./test
            '';
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            gcc
            gdb
            valgrind
          ];
        };

        checks = {
          test = self.packages.${system}.test;
        };
      }
    );
}
