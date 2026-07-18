# dotlock — Roadmap de Execução

Projeto: `/home/filipefreitas/dotlock` — CLI `dl`, gerenciador de segredos/env criptografado, v0.1.6, Rust edition 2024, ~7400 LOC.

Fonte das descobertas: revisão consolidada e deduplicada (5 relatórios independentes), IDs K/H/M/L/A/FG. Estado atual: `cargo test` = 39 pass, `cargo clippy` = 7 warnings, `cargo audit` = 1 vulnerabilidade sem fix (rsa/Marvin), 1 com fix (anyhow), 2 transitivas.

---

## Ordem recomendada de execução

| # | Fase | Escopo | Estimativa | Bloqueia |
|---|------|--------|------------|----------|
| 0 | Correções críticas de data-loss/segurança | K1–K6 | G | Tudo |
| 1 | Endurecimento de segurança | H1–H6 | M | Fase 3 (parcial) |
| 2 | Refatoração de arquitetura | A1–A9 | G | Fases 3–5 (facilita) |
| 3 | Hardening médio | M1–M9 | M | — |
| 4 | Funcionalidades | FG1–FG6 | M/G | — |
| 5 | Polimento | L1–L8, A10, deps, CI | P | — |

> **A Fase 0 não pode ser pulada nem reordenada.** Ela corrige bugs que **destroem vaults de produção hoje** (revogação quebrada, merge que orfana chaves, janelas de crash que deixam o vault permanentemente irrecuperável). Qualquer trabalho de feature ou refatoração feito antes dela corre sobre um alicerce que perde dados. Cada item da Fase 0 entra com teste de regressão obrigatório.

Spec detalhada da Fase 0: [`SPEC-fase-0-criticos.md`](./SPEC-fase-0-criticos.md).

---

## Fase 0 — Correções críticas de data-loss/segurança (K1–K6)

**Objetivo:** eliminar todos os caminhos conhecidos que (a) deixam um destinatário revogado com acesso, (b) tornam segredos ou o vault inteiro permanentemente indecifráveis, ou (c) permitem que um recipient read-only corrompa a integridade do time inteiro.

**Itens:**

- **K1** — `dl share revoke` quebrado para vaults v5+ (envelope/SDK): `reencrypt_secret` descriptografa com o DEK bruto, falha AEAD, comando aborta antes de `save_vault_metadata` → revogado mantém acesso. `src/main.rs:784-808`, `src/main.rs:974-985`. Fix: reusar o caminho correto `rotate_kek_wrapping` (`src/storage/vault_file.rs:54-93`).
- **K2** — Merge driver git orfana SDKs: `merge_metadata` (`src/git/merge.rs:160-226`) nunca mescla `wrapped_sdks_under_kek` nem `wrapped_sdks` por recipient → segredo criado só em `theirs` fica indecifrável para sempre após merge.
- **K3** — Transação de dois arquivos (`secrets.lock` + `vault.toml`) não é atômica em nenhum mutator de `src/storage/secrets_lock.rs` (`upsert_plain_secret:206`, `upsert_many:519`, `upsert_dynamic_secret:601`, `migrate_all_secrets_to_envelope:311`, `rotate_secret_sdks_after_acl_removal:357`, `remove_secret_by_name:712`) e `src/main.rs:930-936` → crash entre as duas gravações = SDK perdido e/ou `TamperedSecretsFile` sem recuperação.
- **K4** — Janela de crash na rotação de KEK/project-key bricka o vault: `rotate_project_key_wrapping` grava o DEK novo e só depois, em segunda gravação (`save_rotated_project_key`), o hash de integridade re-criptografado. `src/main.rs:916-936`, `src/storage/vault_file.rs:54-93`. Também atingido silenciosamente pelo auto-ratchet `prepare_project_key_for_write` (`src/main.rs:901-914`).
- **K5** — Recipient limitado (read-only) pode deletar qualquer segredo e corromper a integridade de todos: `remove_secret_by_name` (`src/storage/secrets_lock.rs:712-745`) não chama `reject_limited_identity_write`; o DEK dummy `[0u8;32]` (`src/storage/unlock_file.rs:105-126`) flui para `build_encrypted_hash_fields`.
- **K6** — Merge driver re-abençoa ou pula silenciosamente o hash de integridade (`src/git/merge.rs:41-57`): recomputa o hash com o DEK local (lavando conteúdo não confiável) ou, sem DEK disponível (CI, cache expirado), pula com `.ok()` → falso `TamperedSecretsFile`.

**Entregável transversal:** primitiva única de escrita transacional do par `vault.toml` + `secrets.lock` (ver `SPEC-fase-0-criticos.md`, seção "Padrão de escrita transacional"), pela qual K1/K3/K4/K6 devem passar, mais o esqueleto do comando `dl repair` (FG6) como rota de recuperação de emergência.

**Critério de conclusão (DoD):**
- Cada K1–K6 tem teste de regressão que falha no código atual e passa após o fix (testes de integração descritos na SPEC).
- `dl share revoke` seguido de `dl get` pelo revogado falha; pelos remanescentes funciona, em vault v5 real.
- Teste de merge com `dl set` divergente em dois branches: todos os segredos decifráveis após merge.
- Kill -9 injetado entre as gravações do par (via fault-injection ou hook de teste) nunca deixa o vault em estado indecifrável — ou é recuperável via `dl repair`.
- `dl unset` por identidade limitada é rejeitado; nenhum caminho de escrita aceita o DEK zero.
- `cargo test` completo verde; nenhuma regressão nos 39 testes existentes.

**Estimativa:** G (grande). É o trabalho mais sutil do roadmap — cripto + atomicidade de FS + merge de três vias.

**Riscos:** mexer na rotação e no formato de gravação pode introduzir novos bugs de compatibilidade com vaults existentes (v5). Mitigar: testes com fixtures de vault gerados pela versão atual; não mudar formato em disco nesta fase (apenas ordem/atomicidade das gravações); `dl repair` como rede de segurança.

---

## Fase 1 — Endurecimento de segurança (H1–H6)

**Objetivo:** fechar as vulnerabilidades exploráveis por um colega malicioso/CI com acesso de escrita ao repo, ou por processo local same-uid.

**Itens:**

- **H1** — Injeção de argumento git via config `auto_fetch_remote` → RCE. `src/git/sync.rs:45,67`, `src/git/fetch.rs:47-50,55`, validação em `src/storage/config.rs:75-82`. Fix: `--` antes de refspecs, rejeitar valores começando com `-`, validar `^[A-Za-z0-9._/-]+$`.
- **H2** — Rollback/replay via `updated_at` não autenticado em `choose_latest` (`src/git/merge.rs:129-146`; timestamp em `secrets_lock.rs:190-198`). Fix: vincular `updated_at`+`id`+`name` em AAD/envelope assinado, ou contadores de versão monotônicos por segredo.
- **H3** — Injeção de recipient via merge → escalada silenciosa de privilégio no próximo rotate. `src/git/merge.rs:192-226`, sink `src/main.rs:798`. Fix: grants de recipient assinados individualmente por chave admin autorizada, verificados no merge; nunca absorver recipient não assinado.
- **H4** — Audit log forjável na config padrão + truncamento de cauda indetectável. `src/audit/log.rs:301-315`, `src/audit/verify.rs:12-68`. Fix: `--strict` como default (exit non-zero em entrada anônima), caminho de assinatura em memória no unlock para identidades criptografadas, high-water mark assinado (count + head hash).
- **H5** — DEK em claro persistido em disco (`src/storage/cache.rs:112-163`, TTL até 1h). Fix: OS keyring / agente memory-only; se o cache em arquivo ficar, envolver sob chave vinculada à máquina/sessão, encurtar TTL, deletar+shred na saída, zeroizar após parse.
- **H6** — `HOME` ausente → `identity.pem` e cache de DEK caem no `./.lock` commitável. `src/storage/identity.rs:34-54`, `src/storage/cache.rs:55-75`, `src/audit/log.rs:317-337`. Fix: hard-fail com erro claro; usar `dirs`/XDG; nunca gravar material de chave no CWD.

**Nota de dependência:** H2 e H3 estendem o trabalho de merge da Fase 0 (K2/K6) — implemente-os enquanto o contexto do merge driver está fresco.

**Critério de conclusão (DoD):**
- Teste: `auto_fetch_remote = "--upload-pack=..."` é rejeitado na leitura da config e na execução.
- Teste de merge: recipient injetado em `theirs` sem assinatura válida é rejeitado; replay de registro antigo com timestamp futuro não vence.
- `dl audit verify` (default) falha com entradas anônimas; teste de truncamento de cauda detectado.
- Nenhum arquivo sob `./.lock` recebe chave privada ou DEK quando `HOME` está ausente (teste com env limpo).
- Documentar no README o modelo de ameaça residual do cache de sessão (se mantido em arquivo).

**Estimativa:** M (médio). H3 e H4 são os mais trabalhosos (formato assinado + migração).

**Riscos:** H3 introduz conceito de "admin key" que não existe hoje — decisão de design (quem assina o primeiro grant?) precisa ser tomada antes de codar; risco de quebrar vaults compartilhados existentes → prever caminho de migração/bless inicial.

---

## Fase 2 — Refatoração de arquitetura (A1–A9)

**Objetivo:** consolidar o código para que a classe de bug da Fase 0 não possa reaparecer, e destravar testabilidade para as fases seguintes.

**Por que DEPOIS das Fases 0/1, e não antes?** Argumento honesto nos dois sentidos:

- *A favor de refatorar primeiro:* muitos fixes críticos tocam exatamente o código duplicado (os 3+1 upserts de A3, a confusão DEK/SDK de A7/A9 que plausivelmente causou K1). Corrigir antes de consolidar significa aplicar o mesmo patch em 3 lugares — churn que a refatoração vai reescrever em seguida.
- *A favor de corrigir primeiro (recomendação):* os bugs K destroem dados de usuários **agora**; cada dia sem fix é risco real. Refatorar um código cujo comportamento correto ainda não está pinado por testes é refatorar às cegas — os testes de regressão da Fase 0 são justamente a rede de segurança que torna a Fase 2 segura. E a primitiva transacional da Fase 0 já É o primeiro passo da consolidação (todos os mutators passam a rotear por um único ponto), reduzindo o churn temido.

**Recomendação de sequenciamento:** Fase 0 primeiro, mas implementada "com a Fase 2 no horizonte": (1) a correção de K1/K3 já extrai o núcleo `upsert_record` único (antecipando A3) em vez de patchear as 3 cópias; (2) introduzir os newtypes `ProjectKey`/`SecretDek` (A7) já na Fase 0 se o fix de K1 se beneficiar do compilador pegando mixups — é mudança mecânica e de baixo risco; (3) o restante da refatoração (A1, A2, A5, A6) espera os testes de regressão existirem.

**Itens:**

- **A1** — Quebrar o god-file `main.rs` (1184 linhas): extrair camada de use-cases entre CLI e storage/crypto; `dispatch()` vira roteamento fino.
- **A2** — Entidades de domínio reais (`SecretRecord`, `VaultKeyMetadata`, `VaultRecipient`, `VaultConfig`, `DynamicSecretMetadata`) em `domain/`, separadas do I/O TOML; regras de negócio testáveis sem FS.
- **A3** — Deduplicar upserts (3 cópias + 1 morta com `#[allow(dead_code)]` sem SDK wrapping): um `upsert_record` central + `persist` fino. *Parcialmente antecipado na Fase 0.*
- **A4** — Remover `anyhow` de `crypto/{kdf,dek,kek}.rs` (erros stringificados via `map_err(|e| Crypto(e.to_string()))`, `source()` nunca populado); thiserror local. Bônus: elimina o RUSTSEC-2026-0190.
- **A5** — Deduplicar renderizador de tabela ×3 (`utils.rs:127-184`, `main.rs:1048-1097`, `unlock_file.rs:128-178`) em `render_table(headers, rows)`.
- **A6** — `VaultContext { metadata, dek }` construído uma vez por comando (hoje `vault.toml` é relido 5×/comando + 2× para nome do cache-dir).
- **A7** — Newtypes `ProjectKey`/`SecretDek` no lugar de `[u8;32]` cru — mixups DEK/SDK (raiz de K1) viram erro de compilação.
- **A8** — Trait de storage in-memory + testes e2e de binário com `assert_cmd` (init→set→get→export→run).
- **A9** — Renomear `wrapped_sdks_under_kek` (na verdade wrapped sob o DEK) e clarificar que `dl rotate` rotaciona o DEK — a confusão de nomes plausivelmente causou K1. Rename apenas em código/identificadores; avaliar impacto no formato TOML em disco (se o nome do campo serializado mudar, exige migração — preferir `#[serde(rename)]` para manter compatibilidade).

**Critério de conclusão (DoD):**
- Nenhuma lógica de upsert/tabela duplicada; `upsert_secret` morto removido.
- `main.rs` < ~300 linhas (clap + roteamento); use-cases com testes unitários sem FS.
- `anyhow` fora da árvore de dependências (ou apenas dev).
- Suite e2e `assert_cmd` cobrindo o fluxo feliz completo.
- Todos os testes de regressão da Fase 0 continuam verdes (é o critério nº 1 — a refatoração não pode regredir os fixes críticos).

**Estimativa:** G. Mudança estrutural ampla, mas mecânica com a rede de testes no lugar.

**Riscos:** regressão de comportamento em caminhos não cobertos por teste — mitigar aumentando cobertura ANTES de mover código (A8 primeiro dentro da fase); rename A9 pode quebrar compat de formato se serializado sem `serde(rename)`.

---

## Fase 3 — Hardening médio (M1–M9)

**Objetivo:** fechar as janelas de corrida, autenticação de metadata e endurecimento de provider/argv, sobre a base já refatorada.

**Itens:**

- **M1** — Lock inter-processo no par do vault (reusar padrão `AuditLock`, `audit/log.rs:97-142`) — elimina lost updates e falsos `TamperedSecretsFile` em `dl set` concorrente.
- **M2** — MAC/assinar metadata inteira do `vault.toml` sob subchave derivada do KEK (`crypto/integrity.rs:110-128`, `unlock_file.rs:117-121`) — hoje recipients limitados confiam no hash em claro gravável pelo atacante.
- **M3** — Proteção anti-rollback: `kek_version` + contador monotônico no AAD do wrapped-DEK; unlock recusa retroceder (`crypto/dek.rs:33,56`).
- **M4** — AAD (id+name) em `secret_cipher.rs:30-74` — impede swap de ciphertext entre segredos legados DEK-direct.
- **M5** — TOCTOU de symlink em `secure_fs` (leitura + componentes do ensure_dir) e `shared_access.rs:201`: `O_NOFOLLOW`/`openat` (`storage/secure_fs.rs:81-128`).
- **M6** — Janela de permissão de diretório: `DirBuilder::mode(0o700)` em vez de create+chmod (`secure_fs.rs:66-73`).
- **M7** — Provider: hash→exec pelo mesmo fd (fexecve); validar nome `^[a-z0-9][a-z0-9_-]*$` (path traversal `../bin/sh`); checar group-writable + ownership; exigir pin sha256 (`providers/mod.rs:33-48,198-260`).
- **M8** — Segredo via argv (`dl set NAME value` visível em ps/`/proc`/history): `--stdin`/prompt sem eco; cobrir flags separadas por espaço em `sanitize_command` (`main.rs:148-159,522-526`, `runtime/mod.rs:36`, `audit/mod.rs:67-83`).
- **M9** — Windows: DACLs restritivas ou documentar a lacuna (todos os blocos `#[cfg(unix)]` em `secure_fs.rs`, `audit/log.rs:82-92`).

**Critério de conclusão (DoD):** teste de concorrência (2 `dl set` paralelos) sem corrupção; teste de swap de ciphertext falha AEAD; teste de rollback de `kek_version` rejeitado; provider com nome traversal rejeitado; `dl set --stdin` funcional e documentado.

**Estimativa:** M.

**Riscos:** M2/M3 mudam formato de metadata → planejar versionamento de vault (v6?) com migração automática no primeiro unlock full-access; M9 pode ser apenas documentação nesta fase.

---

## Fase 4 — Funcionalidades (FG1–FG6)

**Objetivo:** paridade de UX com dotenvx/sops/doppler nos pontos que travam adoção em CI e times, preservando o diferencial FG7 (merge driver nativo para arquivos criptografados).

**Itens:**

- **FG1** — `--json` em `list`/`get`/`share list`/`audit show` (saída machine-readable p/ scripts e CI).
- **FG2** — Unlock não-interativo: `DOTLOCK_PASSWORD`/`--password-stdin`/`--password-file` — hoje o prompt `inquire` é o único caminho e `dl run` trava em CI headless.
- **FG3** — Multi-ambiente de primeira classe (dev/staging/prod) estilo doppler `config` — hoje projeto/env são fixados no `dl init`.
- **FG4** — `dl exec` shell-form / fallback `--env-file` para migração gradual de `.env`/dotenvx.
- **FG5** — Rotação agendada: `dl rotate --if-due` + política em config (complementa o ratchet por contagem de escritas).
- **FG6** — `dl repair` completo (recompute do hash de integridade a partir do `secrets.lock` atual dado um DEK válido) — esqueleto entregue na Fase 0, aqui vira comando polido com UX de diagnóstico. Spec em `SPEC-fase-0-criticos.md`.

**Critério de conclusão (DoD):** pipeline de CI de exemplo (GitHub Actions) no repo usando `--password-stdin` + `--json` de ponta a ponta; `dl exec` documentado; `dl repair` recupera um vault com hash stale em teste.

**Estimativa:** M/G (FG3 é o maior; pode ser fatiado em sub-milestone próprio).

**Riscos:** FG2 amplia superfície de exposição de senha (env vars vazam em logs de CI) — documentar práticas seguras; FG3 mexe no layout do vault → decidir formato antes de FG1 estabilizar contratos JSON.

---

## Fase 5 — Polimento (L1–L8, A10, deps, CI)

**Objetivo:** fechar os itens de baixa severidade, higiene de dependências e automação de qualidade.

**Itens:**

- **L1** — `Zeroizing<String>`/`secrecy` para passphrases e plaintext decifrado (`crypto/mod.rs:156-217`, `unlock_file.rs:94-103`, `secret_cipher.rs:55-74`).
- **L2** — Viés de módulo no gerador de senha (256 % 74): rejection sampling (`crypto/passgen.rs:8-23`).
- **L3** — Erro serde pode ecoar metadata decifrada de segredo dinâmico: erro genérico (`secrets_lock.rs:686-688`).
- **L4** — Audit log: linha final truncada não pode invalidar o log inteiro; fsync após `writeln!` (`audit/log.rs:54-95,160-178`).
- **L5** — Confirmação em ops destrutivas (`unset`, `rotate`, `revoke`): `--yes` + confirm em TTY.
- **L6** — `dl export` grava `.env` em claro sem aviso; checar/atualizar `.gitignore` pós-export (`main.rs:634-674`, `env_file.rs:65-67`) — inclusive o gitignore do próprio repo não cobre `.env`.
- **L7** — `dl get`/`dl list` em TTY: default mascarado (scrollback).
- **L8** — Compares não constant-time em hashes públicos — informacional; documentar decisão.
- **A10** — Zerar os 7 warnings de clippy (`unnecessary_lazy_evaluations` ×3 em secrets_lock.rs:224,543,618; `items_after_test_module` cache.rs:166; needless_borrow).
- **Deps** — Bump `anyhow` (ou já removido na Fase 2/A4); documentar RUSTSEC-2023-0071 (rsa/Marvin, sem fix) e avaliar migração para age/X25519 (`crypto_box`) no wrapping de identidade para eliminar RSA; monitorar fxhash/spin transitivos.
- **CI** — `cargo audit` + `cargo deny` + clippy `-D warnings` + suite completa no CI.

**Critério de conclusão (DoD):** clippy limpo com `-D warnings`; CI verde com audit/deny; decisão registrada (ADR curto) sobre RSA→X25519.

**Estimativa:** P (pequeno), exceto a eventual migração RSA→X25519, que se decidida vira fase própria.

**Riscos:** baixos; a migração de identidade RSA→X25519, se aprovada, quebra compat de identidades existentes — tratar como milestone separado com período de dupla-escrita.

---

## Pontos fortes a preservar (não regredir)

Argon2id 64MiB/t=3 acima do OWASP; XChaCha20-Poly1305 com nonces frescos de 24B; RSA-3072 OAEP + PSS (sem PKCS#1v1.5); envelope SDK por segredo; escritas atômicas de arquivo único (O_EXCL temp + fsync + rename); 0600/0700 desde a criação; zeroize de material de chave; nenhuma execução via shell (arrays argv); sandbox de provider (pin sha256, caps de output, timeout); `.lock/` gitignorado; ACL removal com rotação real de SDK; `ensure_vault_clean` antes de sync. E o diferencial competitivo: **merge driver git nativo para arquivos criptografados (FG7)** — as Fases 0/1 o consertam e endurecem; nunca removê-lo.
