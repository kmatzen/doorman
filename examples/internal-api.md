# Internal HTTPS API through doorman

The client speaks plain HTTP to doorman on loopback; doorman speaks TLS to the upstream by default. Keep `tls: true` (or omit it), even though the URL used by the client starts with `http://`:

```yaml
- name: internal_api
  secret: replace_me
  inject: "Authorization: Bearer {}"
  hosts: [internal-api.example.com]
  methods: [GET]
  # tls: true is the default
```

```sh
export HTTP_PROXY=http://127.0.0.1:18443
curl --proxy "$HTTP_PROXY" \
  -H 'X-Doorman-Cred: internal_api' \
  http://internal-api.example.com/api/v1/jobs/123
```

Set `X-Doorman-Cred`; do not set `Authorization` yourself. Doorman removes the selection header and supplies the configured authorization header upstream.

For an internal service with a self-signed certificate, pin the leaf certificate rather than disabling TLS:

```sh
doormand fingerprint internal-api.example.com
```

Copy the hexadecimal value after `sha256:` into `tls_pinned_sha256` on the credential. Reserve `tls: false` for an upstream that genuinely supports only plaintext HTTP on a trusted local network.
