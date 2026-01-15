# githttps-proxy

A proxy that exposes SSH git repositories over HTTPS. Useful when you need to access git repos via HTTPS but the server only supports SSH.

(Initially I created it to allow CI/CD automation and also self-hosted Gitea mirroring of Github repos without account-wide or repo tokens, which could be problematic and expiring)

## How it works

```
git clone https://username:password@proxy.example.com/git@github.com:owner/repo.git
```

The proxy authenticates you with username/password, then uses the SSH key associated with that user to connect to the target git server.

The proxy users and their SSH keys are distinct and unrelated to the shell users of the system you're running it on, and are specified in the config file. If you want to have access to a specific repo, I recommend using deployment keys for that repo and a dedicated proxy user for that.

## Building

```
go build -o githttps-proxy .
```

## Configuration

Copy `config.example.yaml` to `config.yaml` and edit it:

```yaml
listen: ":443"

tls:
  enabled: true
  self_signed: true  # or use Let's Encrypt / existing certs

users:
  myrepospecialuser:
    password: "plaintextpassword"
    private_key: |
      -----BEGIN OPENSSH PRIVATE KEY-----
      ...
      -----END OPENSSH PRIVATE KEY-----
```

You can also store keys in a directory instead of inline:

```yaml
keys_dir: /etc/githttps-proxy/keys

users:
  myrepospecialuser:
    password: "plaintextpassword"
    # key loaded from /etc/githttps-proxy/keys/myrepospecialuser
```

It is advised against using plaintext passwords and instead use bcrypt hashes for better security. See the section on password hashing below.

### TLS options

**Self-signed** (testing):
```yaml
tls:
  enabled: true
  self_signed: true
```

**Let's Encrypt** (automatic acquisition of certificates):
```yaml
tls:
  enabled: true
  hosts: ["git.example.com"]
  acme_email: "admin@example.com"
```

**Existing certificate** (e.g., certbot already installed and configured):
```yaml
tls:
  enabled: true
  cert_file: /etc/letsencrypt/live/git.example.com/fullchain.pem
  key_file: /etc/letsencrypt/live/git.example.com/privkey.pem
```

The certificate will hot-reload if it changes.

### Password hashing

For better security, use bcrypt hashes instead of plaintext passwords:

```
./githttps-proxy secret mypassword
$2a$10$...
```

Then in config:
```yaml
users:
  alice:
    secret: "$2a$10$..."  # instead of password
```

## CLI

```
githttps-proxy                     # start server
githttps-proxy -config /path/to/config.yaml

githttps-proxy keygen -user alice  # generate SSH key pair (ed25519)
githttps-proxy keygen -user bob -type rsa4096  # generate RSA-4096 key
githttps-proxy pubkey -user alice  # print public key (add to GitHub/GitLab/etc)
githttps-proxy secret PASSWORD     # generate bcrypt hash
```

### Key generation

You can generate SSH keys for users with the `keygen` command:

```
githttps-proxy keygen -user USERNAME [-type TYPE] [-config CONFIG]
```

Supported key types:
- `ed25519` (default) - Modern, secure, compact keys
- `rsa4096` - RSA with 4096 bits, widely compatible
- `ecdsa384` - ECDSA with P-384 curve

If `keys_dir` is configured and the directory exists, the private key is saved there automatically. Otherwise, the key is printed to the console with instructions for adding it to your config.

## Installation (Ubuntu/Debian)

```
CGO_ENABLED=0 go build -o githttps-proxy .
sudo ./install.sh
sudo nano /etc/githttps-proxy/config.yaml
sudo systemctl enable --now githttps-proxy
```

## Cross-compilation

If you are, for example, on macOS, and you want to run it on Linux, you can cross-compile for the target architecture:

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o githttps-proxy-amd64 .

# For an ARM64 machine, you can build for ARM64:
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o githttps-proxy-arm64 .
```

## Usage

Once running, clone repos like this:

```
git clone https://username:password@proxy.example.com/git@github.com:owner/repo.git
git clone https://username:password@proxy.example.com/git@gitlab.com:owner/repo.git
git clone https://username:password@proxy.example.com/git@bitbucket.org:owner/repo.git
```

The path after the proxy host is the SSH URL with `@` and `:` preserved (or URL-encoded). You can also use percent-encoding for the repository part of the URL, for example `git%40github.com%3Aowner%2Frepo.git`.

## License

MIT
