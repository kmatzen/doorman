# GitHub API through doorman

Create a fine-grained personal access token with access only to the repositories and permissions the agent needs. Doorman's method allowlist is an additional boundary; it does not reduce the permissions of an over-scoped token at GitHub.

Use two credential names when an agent usually needs reads but occasionally needs writes:

```yaml
- name: github
  secret: github_pat_replace_me
  inject: "Authorization: Bearer {}"
  hosts: [api.github.com]
  methods: [GET, POST, PUT, PATCH, DELETE]

- name: github_readonly
  secret: github_pat_replace_me
  inject: "Authorization: Bearer {}"
  hosts: [api.github.com]
  methods: [GET, HEAD]
```

The entries may reference the same token, though separate tokens with distinct GitHub permissions provide stronger least privilege. Call the read-only entry with an `http://` URL; doorman establishes verified TLS to GitHub:

```sh
curl --proxy http://127.0.0.1:18443 \
  -H 'X-Doorman-Cred: github_readonly' \
  http://api.github.com/repos/OWNER/REPO/issues
```

For GitHub Enterprise Server, replace `api.github.com` in both `hosts` and the request URL with the API hostname used by your installation, such as `github.example.com`.
