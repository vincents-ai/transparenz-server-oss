{
  description = "Transparenz Server - Deployment infrastructure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages = {
          default = self.packages.${system}.server;

          server = let
            go = pkgs.go_1_25;
            node = pkgs.nodejs_20;
          in pkgs.buildGoModule {
            pname = "transparenz-server";
            version = "0.1.0";
            src = ./.;
            vendorHash = null;
            CGO_ENABLED = 0;
            GOOS = "linux";
            nativeBuildInputs = [ go node ];
          };

          docker-build = pkgs.writeShellScriptBin "docker-build" ''
            #!/bin/sh
            set -e
            cd ./.
            docker build -t transparenz-server:latest .
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_25
            nodejs_20
            postgresql_16
            golangci-lint
            go-migrate
            docker
            docker-compose
            process-compose
          ];

          shellHook = ''
            export DATABASE_URL="postgres://user:pass@localhost:5434/transparenz?search_path=compliance&sslmode=disable"
            export JWT_SECRET="dev-secret-change-in-production"
            export PORT=8080
            export LOG_LEVEL=info
            export ENCRYPTION_KEY="dev-encryption-key-32chars-ok!!!"
            export GRYPE_DB_PATH="/tmp/grype-db"
            export TEST_DATABASE_URL="postgres://user:pass@localhost:5434/transparenz_test?search_path=compliance&sslmode=disable"
            export VULNZ_WORKSPACE_PATH="/var/lib/vulnz/workspace"
            export MAX_SBOM_SIZE="10485760"
          '';
        };
      }
    ) // {
      nixosConfigurations = {
        transparenz-connected = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            ./nixos/default.nix
            {
              services.transparenz-server = {
                enable = true;
                profile = "connected";
                databaseUrl = "postgres://transparenz:transparenz@localhost:5432/transparenz?search_path=compliance";
                jwtSecretPath = "/etc/transparenz-server/jwt-secret";
                encryptionKeyPath = "/etc/transparenz-server/encryption.key";
              };
            }
          ];
        };

        transparenz-airgap = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            ./nixos/default.nix
            {
              services.transparenz-server = {
                enable = true;
                profile = "airgap";
                databaseUrl = "postgres:///transparenz?host=/run/postgresql";
                jwtSecretPath = "/etc/transparenz-server/jwt-secret";
                encryptionKeyPath = "/etc/transparenz-server/encryption.key";
              };
              isoImage.makeUsbBootable = true;
              isoImage.contents = [
                { source = ./scripts; target = "/scripts"; }
              ];
            }
          ];
        };
      };
    };
}
