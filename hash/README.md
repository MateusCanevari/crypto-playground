# Hash

Scripts relacionados a funções de hash e verificação de integridade.

## file_hasher.py
Calcula o hash de arquivos utilizando algoritmos comuns como **SHA-256**, **SHA-512** e **MD5** (este último apenas para compatibilidade).

### Uso
```bash
python hash/file_hasher.py examples/sample.txt
python hash/file_hasher.py examples/sample.txt --algo sha512
python hash/file_hasher.py examples/sample.txt --algo md5
