# SSL Certificates

Place your TLS certificate and private key here:

- `cert.pem` — Full certificate chain (server cert + intermediates)
- `key.pem` — Private key (unencrypted)

## Generate self-signed certs for testing

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=cybernews.local"
```

## Let's Encrypt

Use certbot or acme.sh to obtain certs, then copy `fullchain.pem` → `cert.pem` and `privkey.pem` → `key.pem`.

If no certs are placed here, the app serves HTTP only.
