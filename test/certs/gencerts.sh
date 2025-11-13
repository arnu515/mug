#!/usr/bin/env bash
set -eu

if [ ! -f gleam.toml ]; then
  echo "Please run this script in the project root" >&2
  exit 1
fi

cd test/certs
if [[ (-f server.crt || -f server.key || -f server.csr || -f ca.crt || -f ca.key) && -z "${CI:-}" ]]; then
  echo "A key already exists in test/keys. Please delete it manually to proceed." >&2
  echo "You can do so by running the following command in the project root:" >&2
  echo -e "\tfind test/certs -maxdepth 1 -type f ! -name 'gencerts.sh' -delete" >&2
  exit 1
fi

if ! command -v openssl &> /dev/null; then
  echo "'openssl' is required to generate certificates" >&2
  echo "Please install openssl and run this script again"
  exit 1
fi

echo "Removing exiting certificates..."
find . -maxdepth 1 -type f ! -name 'gencerts.sh' -delete

# echo "Generating the certificate..."

# yes '' | openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes

echo "Generating the CA certificate and key..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -out ca.crt -days 3650 -subj '/C=XX/ST=XX/L=XX/O=XX/OU=XX/CN=Mug Test CA'

echo "Generating another CA certificate and key for invalidate test"
openssl genrsa -out ca_2.key 4096
openssl req -x509 -new -nodes -key ca_2.key -out ca_2.crt -days 3650 -subj '/C=XX/ST=XX/L=XX/O=XX/OU=XX/CN=Mug Test CA'

echo "Generating the certificate key..."
openssl genrsa -out server.key 4096
echo "Generating the certificate request..."
openssl req -new -key server.key -out server.csr -addext "subjectAltName=DNS:localhost, IP:127.0.0.1" -subj '/C=XX/ST=XX/L=XX/O=XX/OU=XX/CN=localhost'
echo "Generating the certificate..."
openssl x509 -req -days 365 -in server.csr -outform pem -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -copy_extensions copy
