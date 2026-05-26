# ctf_crypto.py 使用说明

`ctf_crypto.py` 是本仓库统一的 CTF 加解密/加解码工具，兼容 Python 3。仓库已从零散脚本重构为单入口命令协议，方便在比赛里快速尝试。

## 查看支持算法

```bash
python ctf_crypto.py --list
```

当前支持：

- Base 系列：`base16`、`base32`、`base32hex`、`base36`、`base45`、`base58`、`base62`、`base64`、`base64url`、`base85`、`ascii85`、`base91`
- 字节编码：`hex`、`bin`、`oct`、`dec`
- Web/文本编码：`url`、`html`、`qp`、`unicode`、`punycode`、`jwt`
- 古典密码：`rot13`、`rot47`、`caesar`、`atbash`、`affine`、`vigenere`、`railfence`
- CTF 常见：`morse`、`bacon`、`reverse`、`xor`
- 哈希：`hash`，支持 `md5`、`sha1`、`sha256`、`sha512` 等 `hashlib` 算法

## 统一命令协议

```bash
python ctf_crypto.py <算法> <动作> <文本> [参数]
```

动作包括：

- `encode`：编码或加密
- `decode`：解码或解密
- `brute`：爆破/枚举，当前主要用于凯撒

如果不传 `<文本>`，工具会从标准输入读取：

```bash
echo aGVsbG8= | python ctf_crypto.py base64 decode
```

也可以从文件读取：

```bash
python ctf_crypto.py base64 decode -f cipher.txt
```

## 示例

Base64：

```bash
python ctf_crypto.py base64 encode hello
python ctf_crypto.py base64 decode aGVsbG8=
python ctf_crypto.py base64url encode "a+b/c?"
python ctf_crypto.py base58 encode flag
python ctf_crypto.py base91 encode flag
```

Hex：

```bash
python ctf_crypto.py hex encode flag
python ctf_crypto.py hex decode 666c6167
```

URL：

```bash
python ctf_crypto.py url encode "a b&c"
python ctf_crypto.py url decode a%20b%26c
python ctf_crypto.py unicode encode "你好"
python ctf_crypto.py punycode encode "你好"
python ctf_crypto.py jwt decode eyJhbGciOiJub25lIn0.eyJzdWIiOiJjdGYifQ.
```

凯撒：

```bash
python ctf_crypto.py caesar encode attack --shift 3
python ctf_crypto.py caesar decode dwwdfn --shift 3
python ctf_crypto.py caesar brute khoor
python ctf_crypto.py rot47 encode "Hello!"
python ctf_crypto.py affine encode attack -a 5 -b 8
python ctf_crypto.py affine decode izzisg -a 5 -b 8
```

维吉尼亚：

```bash
python ctf_crypto.py vigenere encode attackatdawn --key lemon
python ctf_crypto.py vigenere decode lxfopvefrnhr --key lemon
```

异或：

```bash
python ctf_crypto.py xor encode flag --key k
python ctf_crypto.py xor decode 0d070a0c --key k
python ctf_crypto.py xor encode flag --key k --output base64
python ctf_crypto.py xor decode DQcKDA== --key k --input base64
```

栅栏：

```bash
python ctf_crypto.py railfence encode WEAREDISCOVERED --rails 3
python ctf_crypto.py railfence decode WECRERDSOEEAIVD --rails 3
```

摩斯：

```bash
python ctf_crypto.py morse encode sos
python ctf_crypto.py morse decode "... --- ..."
```

培根：

```bash
python ctf_crypto.py bacon encode flag
python ctf_crypto.py bacon decode aabab ababa aaaaa abbba
```

哈希：

```bash
python ctf_crypto.py hash encode flag --hash md5
python ctf_crypto.py hash encode flag --hash sha256
```

## 别名兼容

为了兼容仓库里旧脚本命名，新工具支持一些别名：

- `b64` -> `base64`
- `b64url` -> `base64url`
- `b32` -> `base32`
- `b32hex` -> `base32hex`
- `b16` -> `base16`
- `b36` -> `base36`
- `b45` -> `base45`
- `b58` -> `base58`
- `b62` -> `base62`
- `b91` -> `base91`
- `kaisa` -> `caesar`
- `peigen` -> `bacon`
- `zhalan` / `rail` -> `railfence`
- `quote-printable` -> `qp`

## 测试

```bash
python -m pytest
```
