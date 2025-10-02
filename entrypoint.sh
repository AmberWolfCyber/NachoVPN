#!/bin/bash

#if [[ -z "${SERVER_FQDN}" ]]; then
#  echo "Error: SERVER_FQDN is not set or is empty"
#  exit 1
#fi

#if [[ -z "${EXTERNAL_IP}" ]]; then
#  echo "Error: EXTERNAL_IP is not set or is empty"
#  exit 1
#fi

CERT_PATH="/app/certs/server-dns.crt"
KEY_PATH="/app/certs/server-dns.key"

if [[ -n "${SKIP_CERTBOT}" ]]; then
  echo "SKIP_CERTBOT is set. Skipping Certbot execution."
elif [[ -f "$CERT_PATH" && -f "$KEY_PATH" ]]; then
  echo "Certificate and key already exist. Skipping Certbot execution."
else
  # Request a certificate from letsencrypt
  certbot certonly \
    --standalone \
    --preferred-challenges http-01 \
    --register-unsafely-without-email \
    --agree-tos \
    --non-interactive \
    --no-eff-email \
    --domain "$SERVER_FQDN"

  if [[ $? -eq 0 ]]; then
    echo "Certificate successfully generated."

    # Copy the certs
    cp "/etc/letsencrypt/live/$SERVER_FQDN/fullchain.pem" "$CERT_PATH"
    cp "/etc/letsencrypt/live/$SERVER_FQDN/privkey.pem" "$KEY_PATH"

    echo "Certificate and key copied to:"
    echo "  Certificate: $CERT_PATH"
    echo "  Key: $KEY_PATH"
  else
    echo "Certbot failed to generate the certificate."
    exit 2
  fi
fi

echo "Starting nachovpn server"
exec python -m nachovpn.server