# Asymmetric Crypto

Exemplos de criptografia assimétrica.

## rsa_toy.py (educacional)
Implementação **toy** de RSA para estudo de conceitos (keygen, assinatura e verificação).

⚠️ Não usar em produção:
- não utiliza padding seguro (PSS/OAEP)
- tamanhos baixos por padrão (apenas para demo)
- objetivo é aprendizado

### Uso

#### Gerar chaves (toy)
```bash
py asymmetric/rsa_toy.py keygen --bits 512

Assinar um arquivo (SHA-256 do arquivo)
py asymmetric/rsa_toy.py sign --n <N_DEC> --d <D_DEC> --file examples/plaintext.txt

Verificar assinatura
py asymmetric/rsa_toy.py verify --n <N_DEC> --e 65537 --sig-b64 <SIG_B64> --file examples/plaintext.txt
