# Examples

Arquivos e comandos rápidos para testar os módulos do repositório.

## Hash
```bash
py hash/file_hasher.py examples/plaintext.txt --algo sha256

HMAC
py mac/hmac_file.py sign examples/plaintext.txt
# copie key_b64 e mac_b64 e valide:
py mac/hmac_file.py verify examples/plaintext.txt --key-b64 <KEY> --mac-b64 <MAC>

Classic (Caesar)
py classic/caesar_cipher.py encrypt --shift 3 --text "Ataque ao amanhecer!"
py classic/caesar_cipher.py bruteforce --text "Dwdtxh dr dpdqhkhfhu!"

KDF (PBKDF2)
py kdf/pbkdf2_demo.py derive --password "SenhaForte#2026" --iterations 200000 --dklen 32 --algo sha256


touch asymmetric/rsa_toy.py
