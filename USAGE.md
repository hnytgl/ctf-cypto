# ctf_crypto.py 使用说明

`ctf_crypto.py` 是本仓库新增的统一 CTF 加解密/加解码工具，兼容 Python 3。旧脚本仍然保留，新工具提供统一命令协议，方便在比赛里快速尝试。

## 查看支持算法

```bash
python ctf_crypto.py --list
```

当前支持：

- Base 系列：`base16`、`base32`、`base64`、`base85`、`ascii85`
- 字节编码：`hex`、`bin`、`oct`、`dec`
- Web 编码：`url`、`html`、`qp`
- 古典密码：`rot13`、`caesar`、`atbash`、`vigenere`、`railfence`
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
```

凯撒：

```bash
python ctf_crypto.py caesar encode attack --shift 3
python ctf_crypto.py caesar decode dwwdfn --shift 3
python ctf_crypto.py caesar brute khoor
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
- `b32` -> `base32`
- `b16` -> `base16`
- `kaisa` -> `caesar`
- `peigen` -> `bacon`
- `zhalan` / `rail` -> `railfence`
- `quote-printable` -> `qp`

## 测试

```bash
python -m pytest
```
