# LWE-Auth (Authenticated Learning With Errors)

Uma implementação em C de um criptossistema pós-quântico baseado no problema *Learning With Errors (LWE)*. Este projeto integra a matemática de reticulados com autenticação via HMAC-SHA256 e extração direta de entropia do kernel, focando em segurança contra ataques de canal lateral e forja de ciphertext.

## Arquitetura de Segurança

* **Resistência Quântica (LWE):** O núcleo da criptografia baseia-se na injeção de ruído em reticulados multidimensionais, tornando inviável a quebra por algoritmos quânticos como o de Shor.
* **Side-Channel Resistance (Tempo Constante):** O código foi escrito eliminando ramificações dependentes de segredo e operadores de módulo aritmético explícitos, prevenindo *Timing Attacks*.
* **Defesa IND-CCA2:** O ciphertext possui uma camada de integridade assinada via HMAC-SHA256, utilizando chaves derivadas. Modificações em trânsito resultam na rejeição da descriptografia em tempo constante.
* **Entropia de Kernel:** Substituição de PRNGs inseguros por extração de entropia randômica do SO (`getrandom`), mitigando predição de estado inicial.

## Requisitos e Compilação

Requer o compilador GCC e a biblioteca OpenSSL (`libssl-dev` / `openssl`).

```bash
make
