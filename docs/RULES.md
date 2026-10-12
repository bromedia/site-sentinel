# Rules bundles

Sentinel ships with a small built-in rule set that works without any download. `update-rules` replaces it with a maintained bundle.

## Format

`rules.json`:

```json
{
    "version": 12,
    "patterns": [
        { "id": "eval-decoder", "severity": "critical", "regex": "/\\beval\\s*\\(\\s*base64_decode\\s*\\(/i", "description": "eval of an encoded payload", "source": "where this rule came from and its license" }
    ],
    "hashes": [
        { "sha256": "<64 hex characters>", "name": "Malware.Family" }
    ]
}
```

- `severity` is `warning` or `critical`; `regex` is a full PCRE with delimiters and flags. Keep patterns specific; a pattern that matches ordinary code will alert on every deploy.
- `version` must increase with each release. Sentinel refuses a lower version (so an old signed bundle cannot be replayed) and does nothing for an equal one.
- The file is installed byte-for-byte so the signature stays valid.

## Signing and publishing (maintainer)

```
php bin/sign-rules.php keygen                       # once; keep the secret key offline
php bin/sign-rules.php sign rules.json secret.key   # writes rules.json.sig and rules.json.sha256
```

Publish `rules.json`, `rules.json.sig` and `rules.json.sha256` side by side (for example as release assets) and give clients:

```json
"rules_url": "https://example.com/path/rules.json",
"rules_public_key": "<the public key printed by keygen>"
```

Clients with the `sodium` extension verify the ed25519 signature. Clients without it must set `"allow_unsigned_rules": true` to use the `.sha256` file instead; that only guards against corruption, not a compromised rules server, and Sentinel says so each time. Run `update-rules` weekly from cron.

## Licensing of rule sources

Sentinel is open source, but every rule you bundle keeps its own license. Before adding rules from another project (Linux Malware Detect signatures, php-malware-finder, Neo23x0 signature-base, and so on), check that its license allows redistribution and commercial use, keep its attribution, and record the origin and license in each rule's `source` field. The built-in rules in `src/Rules.php` are original to this project.
