#!/bin/sh
# One-shot: a private CA and TLS certificates for the three Wazuh components (volume certs).
set -eu
umask 022
cd /certs
[ -f done ] && exit 0
command -v openssl >/dev/null || apk add --no-cache openssl >/dev/null
SUBJ="/C=US/O=uig-honeypot/OU=demo"
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout root-ca.key -out root-ca.pem -subj "$SUBJ/CN=demo-root-ca" 2>/dev/null
for n in admin wazuh.indexer wazuh.manager wazuh.dashboard; do
  openssl req -newkey rsa:2048 -nodes -keyout "$n.tmp" -out "$n.csr" -subj "$SUBJ/CN=$n" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n' "$n" > "$n.ext"
  openssl x509 -req -in "$n.csr" -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -days 825 -extfile "$n.ext" -out "$n.pem" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "$n.tmp" -out "$n-key.pem"
  rm -f "$n.tmp" "$n.csr" "$n.ext"
done
chmod 644 ./*.pem
touch done
echo "certificates ready"
