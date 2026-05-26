#!/usr/bin/env python3
# coding: utf-8
"""Unified Python 3 CTF crypto encode/decode helper."""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import hashlib
import html
import json
import quopri
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Callable


MORSE_TABLE = {
    "a": ".-",
    "b": "-...",
    "c": "-.-.",
    "d": "-..",
    "e": ".",
    "f": "..-.",
    "g": "--.",
    "h": "....",
    "i": "..",
    "j": ".---",
    "k": "-.-",
    "l": ".-..",
    "m": "--",
    "n": "-.",
    "o": "---",
    "p": ".--.",
    "q": "--.-",
    "r": ".-.",
    "s": "...",
    "t": "-",
    "u": "..-",
    "v": "...-",
    "w": ".--",
    "x": "-..-",
    "y": "-.--",
    "z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
}
MORSE_REVERSE = {value: key for key, value in MORSE_TABLE.items()}

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE91_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)

BACON_TABLE = {
    chr(ord("a") + i): format(i, "05b").replace("0", "a").replace("1", "b")
    for i in range(26)
}
BACON_REVERSE = {value: key for key, value in BACON_TABLE.items()}


@dataclass(frozen=True)
class Algorithm:
    name: str
    description: str
    encode: Callable[[str, argparse.Namespace], str] | None = None
    decode: Callable[[str, argparse.Namespace], str] | None = None
    brute: Callable[[str, argparse.Namespace], str] | None = None


def to_bytes(text: str, encoding: str = "utf-8") -> bytes:
    return text.encode(encoding)


def from_bytes(data: bytes, encoding: str = "utf-8") -> str:
    try:
        return data.decode(encoding)
    except UnicodeDecodeError:
        return data.hex()


def decode_base(data: str, fn: Callable[[bytes], bytes], encoding: str) -> str:
    return from_bytes(fn(to_bytes(data.strip(), "ascii")), encoding)


def encode_base(data: str, fn: Callable[[bytes], bytes], encoding: str) -> str:
    return fn(to_bytes(data, encoding)).decode("ascii")


def base16_encode(data: str, args: argparse.Namespace) -> str:
    return encode_base(data, base64.b16encode, args.encoding)


def base16_decode(data: str, args: argparse.Namespace) -> str:
    return decode_base(data.upper(), base64.b16decode, args.encoding)


def base32_encode(data: str, args: argparse.Namespace) -> str:
    return encode_base(data, base64.b32encode, args.encoding)


def base32_decode(data: str, args: argparse.Namespace) -> str:
    return decode_base(data, base64.b32decode, args.encoding)


def base64_encode(data: str, args: argparse.Namespace) -> str:
    return encode_base(data, base64.b64encode, args.encoding)


def base64_decode(data: str, args: argparse.Namespace) -> str:
    return decode_base(data, base64.b64decode, args.encoding)


def base85_encode(data: str, args: argparse.Namespace) -> str:
    return encode_base(data, base64.b85encode, args.encoding)


def base85_decode(data: str, args: argparse.Namespace) -> str:
    return decode_base(data, base64.b85decode, args.encoding)


def ascii85_encode(data: str, args: argparse.Namespace) -> str:
    return encode_base(data, base64.a85encode, args.encoding)


def ascii85_decode(data: str, args: argparse.Namespace) -> str:
    return decode_base(data, base64.a85decode, args.encoding)


def base64url_encode(data: str, args: argparse.Namespace) -> str:
    encoded = base64.urlsafe_b64encode(to_bytes(data, args.encoding)).decode("ascii")
    return encoded if args.padding else encoded.rstrip("=")


def base64url_decode(data: str, args: argparse.Namespace) -> str:
    padded = data + "=" * (-len(data) % 4)
    return from_bytes(base64.urlsafe_b64decode(padded), args.encoding)


def base32hex_encode(data: str, args: argparse.Namespace) -> str:
    return base64.b32hexencode(to_bytes(data, args.encoding)).decode("ascii")


def base32hex_decode(data: str, args: argparse.Namespace) -> str:
    return from_bytes(base64.b32hexdecode(to_bytes(data.upper(), "ascii")), args.encoding)


def base36_encode(data: str, args: argparse.Namespace) -> str:
    return _base_n_encode(to_bytes(data, args.encoding), "0123456789abcdefghijklmnopqrstuvwxyz")


def base36_decode(data: str, args: argparse.Namespace) -> str:
    return from_bytes(_base_n_decode(data.lower(), "0123456789abcdefghijklmnopqrstuvwxyz"), args.encoding)


def base45_encode(data: str, args: argparse.Namespace) -> str:
    raw = to_bytes(data, args.encoding)
    output = []
    for index in range(0, len(raw), 2):
        chunk = raw[index : index + 2]
        if len(chunk) == 2:
            value = chunk[0] * 256 + chunk[1]
            output.extend(
                [
                    BASE45_ALPHABET[value % 45],
                    BASE45_ALPHABET[(value // 45) % 45],
                    BASE45_ALPHABET[value // (45 * 45)],
                ]
            )
        else:
            value = chunk[0]
            output.extend([BASE45_ALPHABET[value % 45], BASE45_ALPHABET[value // 45]])
    return "".join(output)


def base45_decode(data: str, args: argparse.Namespace) -> str:
    output = bytearray()
    index = 0
    while index < len(data):
        chunk = data[index : index + 3]
        if len(chunk) == 3:
            value = (
                BASE45_ALPHABET.index(chunk[0])
                + BASE45_ALPHABET.index(chunk[1]) * 45
                + BASE45_ALPHABET.index(chunk[2]) * 45 * 45
            )
            output.extend(divmod(value, 256))
            index += 3
        elif len(chunk) == 2:
            value = BASE45_ALPHABET.index(chunk[0]) + BASE45_ALPHABET.index(chunk[1]) * 45
            output.append(value)
            index += 2
        else:
            raise ValueError("invalid base45 length")
    return from_bytes(bytes(output), args.encoding)


def base58_encode(data: str, args: argparse.Namespace) -> str:
    return _base_n_encode(to_bytes(data, args.encoding), BASE58_ALPHABET)


def base58_decode(data: str, args: argparse.Namespace) -> str:
    return from_bytes(_base_n_decode(data, BASE58_ALPHABET), args.encoding)


def base62_encode(data: str, args: argparse.Namespace) -> str:
    return _base_n_encode(to_bytes(data, args.encoding), BASE62_ALPHABET)


def base62_decode(data: str, args: argparse.Namespace) -> str:
    return from_bytes(_base_n_decode(data, BASE62_ALPHABET), args.encoding)


def base91_encode(data: str, args: argparse.Namespace) -> str:
    raw = to_bytes(data, args.encoding)
    bit_queue = 0
    bit_count = 0
    output = []
    for byte in raw:
        bit_queue |= byte << bit_count
        bit_count += 8
        if bit_count > 13:
            value = bit_queue & 8191
            if value > 88:
                bit_queue >>= 13
                bit_count -= 13
            else:
                value = bit_queue & 16383
                bit_queue >>= 14
                bit_count -= 14
            output.append(BASE91_ALPHABET[value % 91])
            output.append(BASE91_ALPHABET[value // 91])
    if bit_count:
        output.append(BASE91_ALPHABET[bit_queue % 91])
        if bit_count > 7 or bit_queue > 90:
            output.append(BASE91_ALPHABET[bit_queue // 91])
    return "".join(output)


def base91_decode(data: str, args: argparse.Namespace) -> str:
    value = -1
    bit_queue = 0
    bit_count = 0
    output = bytearray()
    table = {char: index for index, char in enumerate(BASE91_ALPHABET)}
    for char in data:
        if char not in table:
            continue
        if value < 0:
            value = table[char]
        else:
            value += table[char] * 91
            bit_queue |= value << bit_count
            bit_count += 13 if (value & 8191) > 88 else 14
            while bit_count > 7:
                output.append(bit_queue & 255)
                bit_queue >>= 8
                bit_count -= 8
            value = -1
    if value >= 0:
        output.append((bit_queue | value << bit_count) & 255)
    return from_bytes(bytes(output), args.encoding)


def _base_n_encode(raw: bytes, alphabet: str) -> str:
    if not raw:
        return ""
    base = len(alphabet)
    value = int.from_bytes(raw, "big")
    encoded = []
    while value:
        value, remainder = divmod(value, base)
        encoded.append(alphabet[remainder])
    pad = 0
    for byte in raw:
        if byte == 0:
            pad += 1
        else:
            break
    return alphabet[0] * pad + "".join(reversed(encoded or [alphabet[0]]))


def _base_n_decode(data: str, alphabet: str) -> bytes:
    if not data:
        return b""
    base = len(alphabet)
    value = 0
    for char in data:
        value = value * base + alphabet.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    pad = len(data) - len(data.lstrip(alphabet[0]))
    return b"\x00" * pad + raw


def hex_encode(data: str, args: argparse.Namespace) -> str:
    return to_bytes(data, args.encoding).hex()


def hex_decode(data: str, args: argparse.Namespace) -> str:
    cleaned = data.replace(" ", "").replace("\\x", "")
    return from_bytes(bytes.fromhex(cleaned), args.encoding)


def binary_encode(data: str, args: argparse.Namespace) -> str:
    return " ".join(format(byte, "08b") for byte in to_bytes(data, args.encoding))


def binary_decode(data: str, args: argparse.Namespace) -> str:
    parts = data.replace(",", " ").split()
    return from_bytes(bytes(int(part, 2) for part in parts), args.encoding)


def octal_encode(data: str, args: argparse.Namespace) -> str:
    return " ".join(format(byte, "03o") for byte in to_bytes(data, args.encoding))


def octal_decode(data: str, args: argparse.Namespace) -> str:
    parts = data.replace(",", " ").split()
    return from_bytes(bytes(int(part, 8) for part in parts), args.encoding)


def decimal_encode(data: str, args: argparse.Namespace) -> str:
    return " ".join(str(byte) for byte in to_bytes(data, args.encoding))


def decimal_decode(data: str, args: argparse.Namespace) -> str:
    parts = data.replace(",", " ").split()
    return from_bytes(bytes(int(part, 10) for part in parts), args.encoding)


def url_encode(data: str, args: argparse.Namespace) -> str:
    return urllib.parse.quote(data)


def url_decode(data: str, args: argparse.Namespace) -> str:
    return urllib.parse.unquote(data)


def html_encode(data: str, args: argparse.Namespace) -> str:
    return html.escape(data)


def html_decode(data: str, args: argparse.Namespace) -> str:
    return html.unescape(data)


def qp_encode(data: str, args: argparse.Namespace) -> str:
    return quopri.encodestring(to_bytes(data, args.encoding)).decode("ascii")


def qp_decode(data: str, args: argparse.Namespace) -> str:
    return from_bytes(quopri.decodestring(to_bytes(data, "ascii")), args.encoding)


def unicode_escape_encode(data: str, args: argparse.Namespace) -> str:
    return data.encode("unicode_escape").decode("ascii")


def unicode_escape_decode(data: str, args: argparse.Namespace) -> str:
    return codecs.decode(data, "unicode_escape")


def punycode_encode(data: str, args: argparse.Namespace) -> str:
    return data.encode("punycode").decode("ascii")


def punycode_decode(data: str, args: argparse.Namespace) -> str:
    return data.encode("ascii").decode("punycode")


def jwt_decode(data: str, args: argparse.Namespace) -> str:
    parts = data.strip().split(".")
    decoded = []
    for part in parts[:2]:
        padded = part + "=" * (-len(part) % 4)
        raw = base64.urlsafe_b64decode(padded)
        try:
            decoded.append(json.dumps(json.loads(raw), ensure_ascii=False, indent=2))
        except json.JSONDecodeError:
            decoded.append(from_bytes(raw, args.encoding))
    if len(parts) > 2:
        decoded.append(f"signature(base64url): {parts[2]}")
    return "\n.\n".join(decoded)


def reverse(data: str, args: argparse.Namespace) -> str:
    return data[::-1]


def rot13(data: str, args: argparse.Namespace) -> str:
    return caesar_shift(data, 13)


def rot47(data: str, args: argparse.Namespace) -> str:
    output = []
    for char in data:
        code = ord(char)
        if 33 <= code <= 126:
            output.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            output.append(char)
    return "".join(output)


def caesar_shift(data: str, shift: int) -> str:
    output = []
    for char in data:
        if "a" <= char <= "z":
            output.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            output.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        else:
            output.append(char)
    return "".join(output)


def caesar_encode(data: str, args: argparse.Namespace) -> str:
    return caesar_shift(data, args.shift)


def caesar_decode(data: str, args: argparse.Namespace) -> str:
    return caesar_shift(data, -args.shift)


def caesar_brute(data: str, args: argparse.Namespace) -> str:
    return "\n".join(f"{shift:02d}: {caesar_shift(data, -shift)}" for shift in range(1, 26))


def atbash(data: str, args: argparse.Namespace) -> str:
    output = []
    for char in data:
        if "a" <= char <= "z":
            output.append(chr(ord("z") - (ord(char) - ord("a"))))
        elif "A" <= char <= "Z":
            output.append(chr(ord("Z") - (ord(char) - ord("A"))))
        else:
            output.append(char)
    return "".join(output)


def affine_transform(data: str, a: int, b: int, decrypt: bool = False) -> str:
    inverse = None
    if decrypt:
        inverse = pow(a, -1, 26)
    output = []
    for char in data:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            value = ord(char) - base
            if decrypt:
                value = inverse * (value - b) % 26
            else:
                value = (a * value + b) % 26
            output.append(chr(base + value))
        else:
            output.append(char)
    return "".join(output)


def affine_encode(data: str, args: argparse.Namespace) -> str:
    return affine_transform(data, args.a, args.b, decrypt=False)


def affine_decode(data: str, args: argparse.Namespace) -> str:
    return affine_transform(data, args.a, args.b, decrypt=True)


def vigenere(data: str, key: str, decrypt: bool = False) -> str:
    if not key:
        raise ValueError("vigenere requires --key")
    shifts = [ord(char.lower()) - ord("a") for char in key if char.isalpha()]
    if not shifts:
        raise ValueError("vigenere key must contain letters")

    output = []
    index = 0
    for char in data:
        if char.isalpha():
            shift = shifts[index % len(shifts)]
            if decrypt:
                shift = -shift
            output.append(caesar_shift(char, shift))
            index += 1
        else:
            output.append(char)
    return "".join(output)


def vigenere_encode(data: str, args: argparse.Namespace) -> str:
    return vigenere(data, args.key or "", decrypt=False)


def vigenere_decode(data: str, args: argparse.Namespace) -> str:
    return vigenere(data, args.key or "", decrypt=True)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("xor requires --key")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def xor_encode(data: str, args: argparse.Namespace) -> str:
    result = xor_bytes(to_bytes(data, args.encoding), to_bytes(args.key or "", args.encoding))
    if args.output == "base64":
        return base64.b64encode(result).decode("ascii")
    if args.output == "raw":
        return from_bytes(result, args.encoding)
    return result.hex()


def xor_decode(data: str, args: argparse.Namespace) -> str:
    if args.input == "base64":
        raw = base64.b64decode(data)
    elif args.input == "raw":
        raw = to_bytes(data, args.encoding)
    else:
        raw = bytes.fromhex(data.replace(" ", "").replace("\\x", ""))
    return from_bytes(xor_bytes(raw, to_bytes(args.key or "", args.encoding)), args.encoding)


def morse_encode(data: str, args: argparse.Namespace) -> str:
    words = []
    for word in data.lower().split(" "):
        words.append(" ".join(MORSE_TABLE.get(char, char) for char in word))
    return " / ".join(words)


def morse_decode(data: str, args: argparse.Namespace) -> str:
    words = []
    for word in data.split("/"):
        words.append("".join(MORSE_REVERSE.get(code, code) for code in word.split()))
    return " ".join(words)


def bacon_encode(data: str, args: argparse.Namespace) -> str:
    return " ".join(BACON_TABLE.get(char.lower(), char) for char in data if char != " ")


def bacon_decode(data: str, args: argparse.Namespace) -> str:
    cleaned = data.lower().replace("0", "a").replace("1", "b").replace(" ", "")
    chunks = [cleaned[index : index + 5] for index in range(0, len(cleaned), 5)]
    return "".join(BACON_REVERSE.get(chunk, "?") for chunk in chunks if len(chunk) == 5)


def rail_fence_encode(data: str, args: argparse.Namespace) -> str:
    rails = args.rails
    if rails <= 1:
        return data
    rows = ["" for _ in range(rails)]
    row = 0
    step = 1
    for char in data:
        rows[row] += char
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    return "".join(rows)


def rail_fence_decode(data: str, args: argparse.Namespace) -> str:
    rails = args.rails
    if rails <= 1:
        return data
    pattern = []
    row = 0
    step = 1
    for _ in data:
        pattern.append(row)
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step

    counts = [pattern.count(row_index) for row_index in range(rails)]
    rail_text = []
    offset = 0
    for count in counts:
        rail_text.append(list(data[offset : offset + count]))
        offset += count

    result = []
    positions = [0] * rails
    for row_index in pattern:
        result.append(rail_text[row_index][positions[row_index]])
        positions[row_index] += 1
    return "".join(result)


def hash_text(data: str, args: argparse.Namespace) -> str:
    name = args.hash.lower()
    try:
        hasher = hashlib.new(name)
    except ValueError as exc:
        raise ValueError(f"unsupported hash: {name}") from exc
    hasher.update(to_bytes(data, args.encoding))
    return hasher.hexdigest()


ALGORITHMS: dict[str, Algorithm] = {
    "base16": Algorithm("base16", "Base16 encode/decode", base16_encode, base16_decode),
    "base32": Algorithm("base32", "Base32 encode/decode", base32_encode, base32_decode),
    "base32hex": Algorithm("base32hex", "Base32hex encode/decode", base32hex_encode, base32hex_decode),
    "base64": Algorithm("base64", "Base64 encode/decode", base64_encode, base64_decode),
    "base64url": Algorithm("base64url", "URL-safe Base64 encode/decode", base64url_encode, base64url_decode),
    "base36": Algorithm("base36", "Base36 encode/decode", base36_encode, base36_decode),
    "base45": Algorithm("base45", "Base45 encode/decode", base45_encode, base45_decode),
    "base58": Algorithm("base58", "Base58 encode/decode", base58_encode, base58_decode),
    "base62": Algorithm("base62", "Base62 encode/decode", base62_encode, base62_decode),
    "base85": Algorithm("base85", "Base85 encode/decode", base85_encode, base85_decode),
    "base91": Algorithm("base91", "Base91 encode/decode", base91_encode, base91_decode),
    "ascii85": Algorithm("ascii85", "Ascii85 encode/decode", ascii85_encode, ascii85_decode),
    "hex": Algorithm("hex", "Hex encode/decode", hex_encode, hex_decode),
    "bin": Algorithm("bin", "Binary byte encode/decode", binary_encode, binary_decode),
    "oct": Algorithm("oct", "Octal byte encode/decode", octal_encode, octal_decode),
    "dec": Algorithm("dec", "Decimal ASCII byte encode/decode", decimal_encode, decimal_decode),
    "url": Algorithm("url", "URL percent encode/decode", url_encode, url_decode),
    "html": Algorithm("html", "HTML entity encode/decode", html_encode, html_decode),
    "qp": Algorithm("qp", "Quoted-printable encode/decode", qp_encode, qp_decode),
    "unicode": Algorithm("unicode", "Unicode escape encode/decode", unicode_escape_encode, unicode_escape_decode),
    "punycode": Algorithm("punycode", "Punycode encode/decode", punycode_encode, punycode_decode),
    "jwt": Algorithm("jwt", "Decode JWT header/payload without verification", None, jwt_decode),
    "reverse": Algorithm("reverse", "Reverse string", reverse, reverse),
    "rot13": Algorithm("rot13", "ROT13 transform", rot13, rot13),
    "rot47": Algorithm("rot47", "ROT47 transform", rot47, rot47),
    "caesar": Algorithm("caesar", "Caesar cipher", caesar_encode, caesar_decode, caesar_brute),
    "atbash": Algorithm("atbash", "Atbash cipher", atbash, atbash),
    "affine": Algorithm("affine", "Affine cipher ax+b mod 26", affine_encode, affine_decode),
    "vigenere": Algorithm("vigenere", "Vigenere cipher", vigenere_encode, vigenere_decode),
    "xor": Algorithm("xor", "Repeating-key XOR", xor_encode, xor_decode),
    "morse": Algorithm("morse", "Morse code", morse_encode, morse_decode),
    "bacon": Algorithm("bacon", "Bacon cipher", bacon_encode, bacon_decode),
    "railfence": Algorithm("railfence", "Rail fence cipher", rail_fence_encode, rail_fence_decode),
    "hash": Algorithm("hash", "Hash text with md5/sha1/sha256/sha512/etc", hash_text, None),
}

ALIASES = {
    "b16": "base16",
    "b32": "base32",
    "b32hex": "base32hex",
    "b64": "base64",
    "b64url": "base64url",
    "base64-url": "base64url",
    "b36": "base36",
    "b45": "base45",
    "b58": "base58",
    "b62": "base62",
    "b85": "base85",
    "b91": "base91",
    "binary": "bin",
    "octal": "oct",
    "decimal": "dec",
    "quote-printable": "qp",
    "urlencode": "url",
    "urldecode": "url",
    "htmlentity": "html",
    "unicode-escape": "unicode",
    "rail": "railfence",
    "zhalan": "railfence",
    "kaisa": "caesar",
    "peigen": "bacon",
    "mosi": "morse",
    "morsecode": "morse",
}


def resolve_algorithm(name: str) -> Algorithm:
    key = ALIASES.get(name.lower(), name.lower())
    if key not in ALGORITHMS:
        raise ValueError(f"unknown algorithm: {name}")
    return ALGORITHMS[key]


def read_input(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, "r", encoding=args.encoding, errors="ignore") as handle:
            return handle.read()
    if args.text is not None:
        return args.text
    return sys.stdin.read()


def list_algorithms() -> str:
    lines = ["supported algorithms:"]
    for name in sorted(ALGORITHMS):
        lines.append(f"  {name:<10} {ALGORITHMS[name].description}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CTF crypto encode/decode helper")
    parser.add_argument("algorithm", nargs="?", help="algorithm name, use --list to show all")
    parser.add_argument("action", nargs="?", choices=["encode", "decode", "brute"], help="action")
    parser.add_argument("text", nargs="?", help="input text; stdin is used when omitted")
    parser.add_argument("-f", "--file", help="read input text from file")
    parser.add_argument("-k", "--key", help="key for vigenere/xor")
    parser.add_argument("-s", "--shift", type=int, default=3, help="caesar shift, default 3")
    parser.add_argument("-a", type=int, default=5, help="affine cipher a value, default 5")
    parser.add_argument("-b", type=int, default=8, help="affine cipher b value, default 8")
    parser.add_argument("-r", "--rails", type=int, default=2, help="rail fence rails, default 2")
    parser.add_argument("--hash", default="md5", help="hash algorithm for hash action, default md5")
    parser.add_argument("--input", choices=["hex", "base64", "raw"], default="hex", help="xor decode input format")
    parser.add_argument("--output", choices=["hex", "base64", "raw"], default="hex", help="xor encode output format")
    parser.add_argument("--encoding", default="utf-8", help="text encoding, default utf-8")
    parser.add_argument("--padding", action="store_true", help="keep padding for base64url encode")
    parser.add_argument("--list", action="store_true", help="list supported algorithms")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list:
        print(list_algorithms())
        return 0
    if not args.algorithm or not args.action:
        parser.print_help()
        return 2

    try:
        algorithm = resolve_algorithm(args.algorithm)
        data = read_input(args)
        handler = getattr(algorithm, args.action)
        if handler is None:
            raise ValueError(f"{algorithm.name} does not support {args.action}")
        print(handler(data, args))
        return 0
    except (binascii.Error, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
