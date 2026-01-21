# KDF (Key Derivation Functions)

KDFs transformam uma **senha** em uma **chave criptográfica** forte, usando salt e iterações para dificultar brute force.

## pbkdf2_demo.py
Derivação de chave com **PBKDF2-HMAC** (via `hashlib.pbkdf2_hmac`).

### Uso
```bash
py kdf/pbkdf2_demo.py derive --password "SenhaForte#2026" --iterations 200000 --dklen 32 --algo sha256
py kdf/pbkdf2_demo.py derive --password "SenhaForte#2026" --salt-b64 <SALT> --iterations 200000 --dklen 32 --algo sha256

Observações

Use salt aleatório e único por senha.

Iterações dependem da política/performance (ex.: 100k+).

Para armazenamento de senha em produção, prefira também funções modernas específicas (ex.: Argon2/bcrypt), conforme a política do projeto.

