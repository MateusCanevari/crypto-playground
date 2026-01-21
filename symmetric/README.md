# Symmetric Cryptography

Exemplos de criptografia simétrica com foco em **boas práticas** e uso correto em Segurança da Informação.

## aes_gcm.py
Implementação didática de **AES-GCM (Galois/Counter Mode)**, um modo de operação moderno que fornece:

- **Confidencialidade** (criptografia)
- **Integridade** (detecção de alteração)
- **Autenticidade** (verificação implícita via tag)

AES-GCM é amplamente recomendado por padrões como NIST e utilizado em protocolos modernos (TLS, JWT JWE, etc.).

---

## Funcionalidades
- Geração de chave AES (128/192/256 bits)
- Criptografia de texto ou arquivo
- Descriptografia com verificação de integridade
- Suporte a **AAD (Additional Authenticated Data)**

---

## Uso

### Gerar chave AES-256
```bash
py symmetric/aes_gcm.py gen-key --bytes 32

Criptografar texto

py symmetric/aes_gcm.py encrypt \
  --key-b64 <KEY_B64> \
  --text "mensagem secreta" \
  --aad "v1"

Saída:

nonce_b64: valor único usado na criptografia

ct_b64: ciphertext + tag de autenticação

Descriptografar

py symmetric/aes_gcm.py decrypt \
  --key-b64 <KEY_B64> \
  --nonce-b64 <NONCE_B64> \
  --ct-b64 <CT_B64> \
  --aad "v1"

Observações de Segurança

Nunca reutilize o mesmo nonce com a mesma chave

AAD deve ser idêntico na criptografia e descriptografia

A chave deve ser armazenada de forma segura

Este código é educacional e não substitui bibliotecas de alto nível em produção

Dependências

Este script utiliza a biblioteca:

cryptography

Instalação:

py -m pip install cryptography

Em alguns ambientes Windows, versões muito recentes do Python podem exigir wheels compatíveis ou uso de ambientes virtuais.