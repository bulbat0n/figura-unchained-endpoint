import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PREFIX = "figura-unchained-endpoint-v1"
HOST_RE = re.compile(r"(?=.{4,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(:[0-9]{1,5})?")
BAD_SUFFIXES = (".local", ".internal", ".localhost", ".lan")
KEY_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
NOTE_MAX = 200
MAX_SEQ = 2147483647
ALLOWED_FIELDS = {"v", "seq", "ip", "note", "sig"}
DEFAULT_KEYDIR = os.path.join(os.path.expanduser("~"), ".figura-unchained-keys")


class ToolError(Exception):
    pass


def check_host(ip):
    if not isinstance(ip, str) or not HOST_RE.fullmatch(ip):
        raise ToolError("ip must be a lowercase FQDN with an optional :port (no scheme, path, IP address or localhost)")
    host, _, port = ip.partition(":")
    if port and not 1 <= int(port) <= 65535:
        raise ToolError("port must be between 1 and 65535")
    if host.endswith(BAD_SUFFIXES):
        raise ToolError("this host suffix is not allowed")
    return ip


def check_note(note):
    if not isinstance(note, str) or len(note) > NOTE_MAX or not note.isprintable():
        raise ToolError(f"note must be printable text of at most {NOTE_MAX} characters, without line breaks")
    return note


def check_seq(seq):
    if type(seq) is not int or not 1 <= seq <= MAX_SEQ:
        raise ToolError(f"seq must be an integer between 1 and {MAX_SEQ}")
    return seq


def build_message(seq, ip, note):
    return f"{PREFIX}\n{seq}\n{ip}\n{note}".encode("utf-8")


def public_b64(public_key):
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode("ascii")


def fingerprint(pub_b64):
    return hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:16]


def print_public(name, pub, path=None):
    if path:
        print(f"private key : {path}")
    print(f"public key  : {pub}")
    print(f"fingerprint : {fingerprint(pub)}")
    print(f'java        : static final String KEY_{name.upper().replace("-", "_")} = "{pub}";')


def key_path(keydir, name):
    if not KEY_NAME_RE.fullmatch(name):
        raise ToolError("key name may contain only letters, digits, '_' and '-' (at most 32 characters)")
    return os.path.join(keydir, name + ".key")


def get_passphrase(prompt, confirm=False):
    from_env = os.environ.get("FU_KEY_PASSPHRASE")
    if from_env is not None:
        passphrase = from_env
    else:
        passphrase = getpass.getpass(prompt)
        if confirm and getpass.getpass("repeat passphrase: ") != passphrase:
            raise ToolError("passphrases do not match")
    if not passphrase:
        raise ToolError("an empty passphrase is not allowed")
    return passphrase.encode("utf-8")


def load_private(keydir, name):
    path = key_path(keydir, name)
    if not os.path.isfile(path):
        raise ToolError(f"{path} not found (run keygen first)")
    passphrase = get_passphrase(f"passphrase for key '{name}': ")
    with open(path, "rb") as f:
        pem = f.read()
    try:
        key = serialization.load_pem_private_key(pem, passphrase)
    except (ValueError, TypeError):
        raise ToolError("could not decrypt the key (wrong passphrase?)")
    if not isinstance(key, Ed25519PrivateKey):
        raise ToolError("the key is not an Ed25519 key")
    return key


def load_public(pub_b64):
    try:
        key = serialization.load_der_public_key(base64.b64decode(pub_b64, validate=True))
    except (ValueError, binascii.Error):
        raise ToolError("invalid public key (expected base64 of an X.509 SubjectPublicKeyInfo)")
    if not isinstance(key, Ed25519PublicKey):
        raise ToolError("the public key is not an Ed25519 key")
    return key


def parse_document(data):
    if not isinstance(data, dict) or set(data) - ALLOWED_FIELDS:
        raise ToolError("the document must be a JSON object with only: v, seq, ip, note, sig")
    if type(data.get("v")) is not int or data["v"] != 1:
        raise ToolError("unsupported version (v must be 1)")
    seq = check_seq(data.get("seq"))
    ip = check_host(data.get("ip"))
    note = check_note(data.get("note", ""))
    sig = data.get("sig")
    if not isinstance(sig, str):
        raise ToolError("sig must be a base64 string")
    try:
        raw = base64.b64decode(sig, validate=True)
    except binascii.Error:
        raise ToolError("sig is not valid base64")
    if len(raw) != 64:
        raise ToolError("sig must decode to exactly 64 bytes")
    return seq, ip, note, raw


def match_signature(pubs, seq, ip, note, sig):
    message = build_message(seq, ip, note)
    for index, pub in enumerate(pubs):
        try:
            pub.verify(sig, message)
            return index
        except InvalidSignature:
            continue
    return None


def read_previous_seq(path):
    try:
        with open(path, encoding="utf-8") as f:
            seq = json.load(f).get("seq")
    except (OSError, ValueError, AttributeError):
        return None
    return seq if type(seq) is int else None


def cmd_keygen(args):
    path = key_path(args.keydir, args.name)
    if os.path.exists(path):
        raise ToolError(f"{path} already exists, refusing to overwrite it")
    passphrase = get_passphrase(f"passphrase for the new key '{args.name}': ", confirm=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
    os.makedirs(args.keydir, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = public_b64(key.public_key())
    with open(path[:-4] + ".pub", "w", encoding="ascii") as f:
        f.write(pub + "\n")
    print_public(args.name, pub, path)


def cmd_pub(args):
    key = load_private(args.keydir, args.name)
    print_public(args.name, public_b64(key.public_key()))


def cmd_sign(args):
    ip = check_host(args.ip)
    note = check_note(args.note)
    seq = check_seq(args.seq)
    if os.path.exists(args.out) and not args.force:
        previous = read_previous_seq(args.out)
        if previous is not None and seq <= previous:
            raise ToolError(f"seq must be greater than the current {previous} in {args.out} (use --force to override)")
    key = load_private(args.keydir, args.key)
    message = build_message(seq, ip, note)
    signature = key.sign(message)
    key.public_key().verify(signature, message)
    document = {"v": 1, "seq": seq, "ip": ip}
    if note:
        document["note"] = note
    document["sig"] = base64.b64encode(signature).decode("ascii")
    text = json.dumps(document, separators=(",", ":")) + "\n"
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="ascii") as f:
        f.write(text)
    os.replace(tmp, args.out)
    print(f"written {args.out}: seq={seq} ip={ip}" + (f" note={note!r}" if note else ""))
    print(f"signed with key '{args.key}' (fingerprint {fingerprint(public_b64(key.public_key()))})")


def cmd_verify(args):
    try:
        with open(args.file, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise ToolError(f"cannot read {args.file}: {e}")
    seq, ip, note, sig = parse_document(data)
    index = match_signature([load_public(p) for p in args.pub], seq, ip, note, sig)
    if index is None:
        raise ToolError("the signature does not match any of the given public keys")
    print(f"OK seq={seq} ip={ip} signed by public key #{index + 1}" + (f" note={note!r}" if note else ""))


def build_parser():
    parser = argparse.ArgumentParser(prog="sign.py", description="Key management and signing for endpoint.json")
    parser.add_argument("--keydir", default=DEFAULT_KEYDIR, help="directory with private keys (must be given before the command)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate a new encrypted Ed25519 key pair")
    p.add_argument("name")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("pub", help="print the public key of an existing private key")
    p.add_argument("name")
    p.set_defaults(func=cmd_pub)

    p = sub.add_parser("sign", help="sign a new endpoint.json")
    p.add_argument("ip", help="host[:port] of the backend, for example figura-unchained.alwaysdata.net")
    p.add_argument("seq", type=int, help="must be greater than the seq currently published")
    p.add_argument("--key", default="main", help="name of the private key (default: main)")
    p.add_argument("--note", default="", help="optional text shown to users in the consent window")
    p.add_argument("--out", default="endpoint.json")
    p.add_argument("--force", action="store_true", help="allow a seq that is not greater than the current one")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="check an endpoint.json against public keys")
    p.add_argument("file", nargs="?", default="endpoint.json")
    p.add_argument("--pub", action="append", required=True, help="base64 public key, may be repeated")
    p.set_defaults(func=cmd_verify)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
