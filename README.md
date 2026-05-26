# ctf-cypto
network security CTF hacker 
一些常见的编码算法，这里包括，培根解密，凯撒，rot13，base16/32/64，xxencode，quote-printable，摩斯密码，,变形凯撒等等，大家有兴趣可以自行研究。

## 新增统一工具

新增 `ctf_crypto.py`，把仓库里的常见加解密/加解码能力整理成一个统一命令入口，支持 Python 3。

查看支持算法：

```bash
python ctf_crypto.py --list
```

统一调用协议：

```bash
python ctf_crypto.py <算法> <encode|decode|brute> <文本> [参数]
```

示例：

```bash
python ctf_crypto.py base64 decode aGVsbG8=
python ctf_crypto.py caesar brute khoor
python ctf_crypto.py xor encode flag --key k
python ctf_crypto.py vigenere decode lxfopvefrnhr --key lemon
```

详细说明见 [USAGE.md](USAGE.md)。
