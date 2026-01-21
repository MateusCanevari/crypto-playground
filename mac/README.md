# MAC (HMAC)

Scripts para autenticação e integridade de dados utilizando **HMAC**.

HMAC (Hash-based Message Authentication Code) garante que um arquivo:
- não foi alterado (integridade)
- foi gerado por quem possui a chave secreta (autenticidade)

## hmac_file.py
Gera e verifica HMAC de arquivos usando **SHA-256** por padrão.

### Uso

#### Assinar arquivo
```bash
python mac/hmac_file.py sign examples/sample.txt

Saída:

key_b64: chave secreta (base64)

mac_b64: HMAC do arquivo

python mac/hmac_file.py verify examples/sample.txt \
  --key-b64 <KEY_B64> \
  --mac-b64 <MAC_B64>


Observações

Qualquer alteração no arquivo invalida o HMAC.

A chave secreta deve ser armazenada com segurança.

