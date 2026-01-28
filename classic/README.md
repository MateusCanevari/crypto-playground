# Classic Ciphers

Implementações de algoritmos criptográficos **clássicos**, com finalidade
**educacional e histórica**.

Esses algoritmos **não são seguros** para uso real, mas são fundamentais para
entender conceitos básicos de criptografia como substituição, chave e ataque
por força bruta.

---

## caesar_cipher.py

Implementação da **Cifra de César**, um algoritmo de substituição simples baseado
em deslocamento (shift) do alfabeto.

### Funcionalidades
- Criptografar texto com deslocamento definido
- Descriptografar texto com o deslocamento correto
- Ataque de **bruteforce** testando todos os shifts possíveis (0–25)
- Compatível com Windows (tratamento de `carriage return`)

---

### Uso

#### Criptografar
```bash
py classic/caesar_cipher.py encrypt --shift 3 --text "Ataque ao amanhecer!"

Saída:
Dwdtxh dr dpdqhkhfhu!

Descriptografar
py classic/caesar_cipher.py decrypt --shift 3 --text "Dwdtxh dr dpdqhkhfhu!"

Saída:
Ataque ao amanhecer!

Observações de Segurança

A Cifra de César é trivialmente quebrável

O bruteforce funciona porque o espaço de chaves é muito pequeno

Implementação incluída apenas para estudo

Contexto

Este módulo faz parte do repositório crypto-playground, que reúne
implementações práticas de algoritmos criptográficos com foco em aprendizado
e portfólio em Segurança da Informação.