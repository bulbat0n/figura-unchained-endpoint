# figura-unchained-endpoint

This repository holds a single signed file, `endpoint.json`. The Figura Unchained addon downloads it to find out which backend a user who chose the public server should talk to. The file is public on purpose. Only the person holding the private key can produce a file the addon will accept.

## File format

```json
{"v":1,"seq":1,"ip":"figura-unchained.alwaysdata.net","sig":"<base64, 64 bytes>"}
```

| field | type | meaning |
|---|---|---|
| `v` | integer | format version, always `1` |
| `seq` | integer, 1 to 2147483647 | grows with every published change, clients ignore anything not greater than what they already accepted |
| `ip` | string | `host[:port]` of the backend, see host rules |
| `note` | string, optional | plain text shown to the user in the consent window when the address changes, at most 200 characters, printable, no line breaks |
| `sig` | string | base64 of a 64-byte Ed25519 signature |

No other fields are allowed. A file with unknown fields, wrong types or a bad signature is treated as invalid and ignored.

## What is signed

The signature covers exactly these bytes, UTF-8 encoded, with `\n` as the separator and no trailing newline after the last line:

```
figura-unchained-endpoint-v1
<seq as a decimal integer>
<ip>
<note, empty string when the field is absent>
```

The message is signed directly with Ed25519 (no pre-hashing). The JSON text itself is never signed, so whitespace and key order do not matter. Public keys are distributed as base64 of an X.509 `SubjectPublicKeyInfo` structure, which Java loads with `X509EncodedKeySpec` and `KeyFactory.getInstance("Ed25519")`.

## Host rules

`ip` must match all of the following, otherwise the file is invalid:

* lowercase fully qualified domain name, labels of letters, digits and `-`, last label letters only
* optional `:port`, 1 to 65535
* no scheme, path, query, `@`, spaces or IP addresses, and not `localhost`
* must not end with `.local`, `.internal`, `.localhost` or `.lan`
* 4 to 253 characters

The addon always reaches the host over HTTPS.

## Keys

Two Ed25519 keys are used and both public keys are compiled into the addon. A file is valid when it verifies against either of them.

* `main` signs everything day to day. Keep it on the machine you publish from, protected by a passphrase.
* `backup` is created once, ideally on a different machine, copied to offline storage and removed from the publishing machine. It is only used if `main` is lost or leaked.

Private keys live in `~/.figura-unchained-keys/` by default (mode `0600`, passphrase-encrypted PKCS#8). Never commit them. `.gitignore` already excludes `*.key` and `*.pem`.

## Setup

```
pip install -r tools/requirements.txt

python tools/sign.py keygen main
python tools/sign.py keygen backup
```

Each command prints the public key, a fingerprint and a ready-to-paste Java constant. Both public keys go into the addon source. The same public keys are stored next to the private ones as `*.pub`.

Publish the first file:

```
python tools/sign.py sign figura-unchained.alwaysdata.net 1
python tools/sign.py verify --pub <main public key> --pub <backup public key>
git add endpoint.json
git commit -m "endpoint seq 1"
git push
```

The addon fetches `https://raw.githubusercontent.com/<user>/<repo>/main/endpoint.json`. GitHub may serve a cached copy for a few minutes after a push.

`--keydir` changes where private keys are read from and must be written before the command (`python tools/sign.py --keydir /path sign ...`). The passphrase is asked interactively. For automation only, it can be provided in the `FU_KEY_PASSPHRASE` environment variable.

## Moving the backend

```
python tools/sign.py sign new-host.example.net 2 --note "The server moved to a new provider."
python tools/sign.py verify --pub <main> --pub <backup>
git commit -am "endpoint seq 2" && git push
```

`sign` refuses a `seq` that is not greater than the one in the existing `endpoint.json`. Every user whose approved address differs from the new one is asked for consent again and has no network access to the backend until they answer. Pointing the file at a host with very different terms needs a new addon release as well, because the long legal text in the consent window is part of the addon, while `note` is only a short explanation.

## If a key is lost or leaked

* `main` lost, `backup` intact: sign with `--key backup`. Then ship an addon release that replaces the lost key with a new one.
* `main` leaked: treat the file as untrusted until a new addon release drops the leaked key. Old addon versions keep trusting it. A leaked key alone cannot silently move users, because the addon asks for consent whenever the signed address changes.
* `backup` leaked: generate a new backup key and ship it in the next release.

## Checking a file by hand

```
python tools/sign.py verify endpoint.json --pub <public key>
```

prints `OK` with the seq, host and which key matched, or an error and a non-zero exit code.
