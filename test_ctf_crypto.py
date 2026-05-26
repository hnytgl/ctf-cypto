import ctf_crypto


def run(*args):
    return ctf_crypto.main(list(args))


def test_base64_roundtrip(capsys):
    assert run("base64", "encode", "hello") == 0
    encoded = capsys.readouterr().out.strip()
    assert encoded == "aGVsbG8="

    assert run("base64", "decode", encoded) == 0
    assert capsys.readouterr().out.strip() == "hello"


def test_caesar_brute_contains_plaintext(capsys):
    assert run("caesar", "brute", "khoor") == 0
    output = capsys.readouterr().out
    assert "03: hello" in output


def test_vigenere_roundtrip(capsys):
    assert run("vigenere", "encode", "attackatdawn", "--key", "lemon") == 0
    encoded = capsys.readouterr().out.strip()
    assert encoded == "lxfopvefrnhr"

    assert run("vigenere", "decode", encoded, "--key", "lemon") == 0
    assert capsys.readouterr().out.strip() == "attackatdawn"


def test_xor_roundtrip(capsys):
    assert run("xor", "encode", "flag", "--key", "k") == 0
    encoded = capsys.readouterr().out.strip()

    assert run("xor", "decode", encoded, "--key", "k") == 0
    assert capsys.readouterr().out.strip() == "flag"


def test_rail_fence_roundtrip(capsys):
    assert run("railfence", "encode", "WEAREDISCOVERED", "--rails", "3") == 0
    encoded = capsys.readouterr().out.strip()
    assert encoded == "WECRERDSOEEAIVD"

    assert run("railfence", "decode", encoded, "--rails", "3") == 0
    assert capsys.readouterr().out.strip() == "WEAREDISCOVERED"
