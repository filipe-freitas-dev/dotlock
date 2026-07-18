# dotlock — Revisão Completa de Código

**Data:** 2026-07-18 · **Escopo:** projeto `/home/filipefreitas/dotlock` (CLI `dl`, v0.1.6, edition 2024, ~7400 LOC) — segurança, criptografia, arquitetura, qualidade, performance, bugs ocultos, dependências e lacunas de funcionalidade · **Método:** 5 revisores independentes em paralelo, achados deduplicados e consolidados, complementados por `cargo test` (39 pass), `cargo clippy` (7 warnings) e `cargo audit`.

**Contexto do sistema:** gerenciador de secrets/env criptografados por projeto. Hierarquia de chaves: senha → chave-mestre Argon2id → KEK HKDF-SHA256 → envolve o DEK do projeto → chaves SDK por secret envolvidas sob o DEK. Vault = `.lock/vault.toml` (metadados, commitado/compartilhado) + `.lock/secrets.lock` (registros de ciphertext, commitado/compartilhado). Cache de sessão do DEK em `~/.lock/run/sessions/`. Identidades RSA-3072 para compartilhamento. Merge driver do git para arquivos criptografados. Protocolo de provider por subprocesso (`dotlock-provider-<name>`) para secrets dinâmicos. Log de auditoria em hash-chain.

**Modelo de ameaça adotado nas severidades:** vault compartilhado — atacante = colega de equipe/CI com acesso de escrita ao repositório, ou processo local com o mesmo uid.

---

## Sumário Executivo

A base criptográfica do dotlock é sólida e acima da média para um projeto neste estágio: Argon2id com parâmetros acima das recomendações OWASP, XChaCha20-Poly1305 com nonces frescos de 24 bytes, RSA-3072 OAEP/PSS sem PKCS#1v1.5, zeroização de material de chave, escritas atômicas de arquivo único e ausência de exec via shell. Porém, o risco geral atual é **CRÍTICO**: existem 6 achados Tier 0 que quebram garantias centrais do produto — a revogação de acesso (`dl share revoke`) está funcionalmente quebrada em vaults v5+ (o revogado mantém acesso), o merge driver do git pode tornar secrets permanentemente indecifráveis e "abençoar" conteúdo adulterado, e há múltiplas janelas de crash não-atômicas entre `secrets.lock` e `vault.toml` que podem inutilizar o vault de toda a equipe sem caminho de recuperação (`TamperedSecretsFile`). No Tier 1, destacam-se injeção de argumentos git via config commitada (potencial RCE), escalada de privilégio via merge de recipients não autenticados e o DEK em texto claro persistido em disco. A recomendação é congelar features e tratar K1–K6 e H1–H6 antes de qualquer release, adicionando em paralelo um comando `dl repair` e testes de integração binários (init→set→get→revoke→merge).

### Contagem por severidade (achados de segurança e correção)

| Severidade | Tier | Quantidade | IDs |
|---|---|---|---|
| **Critical** | Tier 0 | **6** | K1–K6 |
| **High** | Tier 1 | **6** | H1–H6 |
| **Medium** | Tier 2 | **9** | M1–M9 |
| **Low/Info** | Tier 3 | **8** | L1–L8 |
| **Total** | — | **29** | — |

À parte das contagens de segurança: **4** achados de dependências/supply chain, **10** achados de arquitetura/qualidade (A1–A10) e **7** lacunas de funcionalidade (FG1–FG7).

---

## Achados de Segurança e Correção

### TIER 0 — CRÍTICO: correção / perda de dados / garantia de segurança quebrada (corrigir primeiro)

---

#### K1. `dl share revoke` está quebrado para secrets com envelope encryption (vaults v5+) — o recipient revogado mantém acesso

- **Severidade:** 🔴 Critical
- **Arquivo(s):** `src/main.rs:784-808` (handler de Revoke), `src/main.rs:974-985` (`reencrypt_secret`)

**Descrição.** `reencrypt_secret` descriptografa cada registro com o DEK bruto do projeto, mas desde o vault v5 todo secret é criptografado sob uma SDK por-secret envolvida em `metadata.wrapped_sdks_under_kek`. A descriptografia falha na verificação AEAD, o comando Revoke inteiro aborta ANTES de `save_vault_metadata`, e o `wrapped_dek_b64` / `wrapped_sdks` do recipient permanecem no `vault.toml` compartilhado. Mesmo que "funcionasse", `wrapped_sdks_under_kek` nunca é re-envolvido para o novo DEK → o vault ficaria indecifrável.

**Cenário de ataque/falha.** A revogação falha silenciosamente em todo vault real; um colega revogado/malicioso retém capacidade total de descriptografia dos secrets do projeto.

**Correção.** Reutilizar o caminho correto de `rotate_kek_wrapping` (`src/storage/vault_file.rs:54-93`): desembrulhar cada SDK sob o DEK antigo, re-embrulhar sob o novo DEK, atualizar `wrapped_sdks_under_kek` E os `wrapped_sdks` de cada recipient remanescente, e então re-criptografar o hash de integridade sob o novo DEK na MESMA escrita atômica. Adicionar teste de integração: setar secrets pelo caminho normal → revoke → get.

---

#### K2. Merge driver do git orfana chaves de secrets — secrets mesclados tornam-se permanentemente indecifráveis

- **Severidade:** 🔴 Critical
- **Arquivo(s):** `src/git/merge.rs:160-226` (`merge_vault_metadata`/`merge_metadata`/`merge_recipients`)

**Descrição.** O merge faz union dos registros de `secrets.lock`, mas `merge_metadata` só reconcilia `project_uuid`/`kek_version`/`version`/recipients — NUNCA mescla `wrapped_sdks_under_kek`, nem adiciona entradas faltantes aos `wrapped_sdks` de um recipient existente. Um secret adicionado apenas em `theirs` tem sua SDK wrapping somente no `vault.toml` de theirs, que é descartado (o merge parte de `ours`).

**Cenário de ataque/falha.** Após o merge, `secret_sdk_from_project_key` não encontra nada, cai no fallback `.unwrap_or(*dek)`, o AEAD falha → o secret é perdido para sempre.

**Correção.** Mesclar `wrapped_sdks_under_kek` (union por id de secret) e os `wrapped_sdks` por recipient; conduzir os merges de `secrets.lock` e `vault.toml` a partir de um único passo coordenado, de forma que todo id de secret mesclado tenha uma SDK wrapping. Adicionar teste de merge com `dl set` divergente em ambos os branches.

---

#### K3. Transação não-atômica de dois arquivos (`secrets.lock` + `vault.toml`) → perda de dados ou lockout permanente por "tamper"

- **Severidade:** 🔴 Critical
- **Arquivo(s):** todos os mutadores em `src/storage/secrets_lock.rs` (`upsert_plain_secret:206`, `upsert_many:519`, `upsert_dynamic_secret:601`, `migrate_all_secrets_to_envelope:311`, `rotate_secret_sdks_after_acl_removal:357`, `remove_secret_by_name:712`); também `src/main.rs:930-936`

**Descrição.** Cada escrita de arquivo é atômica (fsync+rename), mas o PAR não é. Crash entre a escrita #1 (`secrets.lock`, conteúdo novo) e a escrita #2 (`vault.toml` com nova SDK wrapping + hash re-criptografado) resulta em: (a) a SDK do novo secret é perdida → ciphertext indecifrável, e/ou (b) `vault.toml` fica com hash obsoleto → o próximo unlock em `verify_secrets_integrity` detecta divergência → `TamperedSecretsFile` bloqueia a equipe inteira, sem caminho de recuperação.

**Cenário de ataque/falha.** Queda de energia, kill ou crash entre as duas escritas em qualquer operação de mutação corrompe o vault de forma irreversível para todos.

**Correção.** Tornar o par transacional (escrever ambos os temporários, fsync em ambos, rename em ambos; ou um journal/marcador de pendência); escrever metadata+hash+SDK do `vault.toml` ANTES de commitar `secrets.lock`; entregar um comando `dl repair` com caminho de recomputação.

---

#### K4. Janela de crash na rotação de KEK/chave do projeto inutiliza o vault

- **Severidade:** 🔴 Critical
- **Arquivo(s):** `src/main.rs:916-936` (`rotate_project_key_wrapping`, `save_rotated_project_key`), `src/storage/vault_file.rs:54-93` (`rotate_kek_wrapping` NÃO toca em `secrets_hash_*`)

**Descrição.** A rotação escreve o `vault.toml` com o novo DEK envolvido primeiro, mas re-criptografa o hash de integridade sob o novo DEK apenas em uma SEGUNDA escrita separada (`save_rotated_project_key`). Crash entre as duas → `wrapped_dek` é novo, mas `secrets_hash` ainda está criptografado sob o DEK antigo (agora irrecuperável) → `TamperedSecretsFile` permanente. Isso também é atingido silenciosamente pelo auto-ratchet de `prepare_project_key_for_write` (`main.rs:901-914`) em escritas comuns.

**Cenário de ataque/falha.** Um `dl set` corriqueiro que dispare o ratchet de rotação, interrompido no momento errado, bloqueia o vault de toda a equipe permanentemente.

**Correção.** Definir o novo `secrets_hash_*` (criptografado sob o novo DEK) no MESMO objeto de metadata e na MESMA chamada de `save_vault_metadata` do rewrap — uma única escrita atômica commita ambos.

---

#### K5. Recipients limitados (somente-leitura) podem deletar qualquer secret e corromper a integridade para todos

- **Severidade:** 🔴 Critical
- **Arquivo(s):** `src/storage/secrets_lock.rs:712-745` (`remove_secret_by_name` — verificação ausente), `src/storage/unlock_file.rs:105-126` (recipient limitado recebe DEK dummy `[0u8;32]`), `src/main.rs:567-576`

**Descrição.** Os upserts chamam `reject_limited_identity_write`; `remove_secret_by_name` (usado por `dl unset`) NÃO chama. O unlock de um recipient limitado retorna um DEK falso todo-zeros, que flui para `build_encrypted_hash_fields`, escrevendo um hash de integridade criptografado sob a chave zero.

**Cenário de ataque/falha.** Um usuário somente-leitura executa `dl unset` em qualquer secret; o próximo unlock com acesso pleno falha no AEAD → `TamperedSecretsFile`, equipe inteira bloqueada — além da deleção não autorizada em si.

**Correção.** Chamar `reject_limited_identity_write` em `remove_secret_by_name` e em todo caminho mutante; fazer o unlock de identidade limitada retornar um tipo distinto (enum / `Option`) em vez de uma chave-zero mágica, para que nunca possa fluir para uma escrita; rejeitar a construção do hash quando `dek == zero placeholder`.

---

#### K6. Merge driver do git "re-abençoa" / pula silenciosamente o hash de integridade → evidência de adulteração derrotada ou falso lockout

- **Severidade:** 🔴 Critical
- **Arquivo(s):** `src/git/merge.rs:41-57` (`merge_secrets_lock`)

**Descrição.** Após mesclar o `theirs` não-confiável, o driver recomputa o hash de integridade (chaveado pelo DEK) com o DEK do usuário LOCAL — "lavando" qualquer resultado do merge (incluindo entradas replayadas/revertidas) para um estado "válido". Inversamente, quando nenhum DEK está disponível (git pull/rebase não-interativo, CI, ou cache expirado — TTL padrão 30s), ele SILENCIOSAMENTE pula o refresh (`.ok()` engole a falha) → o conteúdo mesclado não bate mais com o hash armazenado → o próximo `dl` = `TamperedSecretsFile`.

**Cenário de ataque/falha.** (a) Atacante injeta conteúdo adulterado via merge e o driver o assina como legítimo; (b) merge honesto em CI/headless resulta em falso lockout de tamper para toda a equipe.

**Correção.** Não fazer auto-refresh dentro do driver; exigir um reconcile interativo explícito no `dl` que mostre um diff e re-assine apenas mediante confirmação. Tratar "sem DEK" como erro rígido de merge (deixar conflict markers), não como sucesso silencioso.

---

### TIER 1 — HIGH: fraquezas de segurança exploráveis

---

#### H1. Injeção de argumentos git via config `auto_fetch_remote` → RCE

- **Severidade:** 🟠 High
- **Arquivo(s):** `src/git/sync.rs:45,67`, `src/git/fetch.rs:47-50,55`; validação em `src/storage/config.rs:75-82`

**Descrição.** `remote`/`branch` vindos do `vault.toml` commitado são passados posicionalmente ao git sem separador `--` e com apenas uma checagem de não-vazio.

**Cenário de ataque/falha.** Um valor como `--upload-pack=<cmd>` (ou `ext::sh -c`) executa código do atacante na máquina da vítima no próximo auto-fetch (`dl run`) ou `dl sync`. Qualquer pessoa com escrita no repo obtém RCE nos colegas.

**Correção.** Inserir `--` antes dos refspecs; rejeitar valores começando com `-`; validar contra `^[A-Za-z0-9._/-]+$`.

---

#### H2. Rollback/replay/overwrite via `updated_at` não autenticado na resolução de conflitos de merge

- **Severidade:** 🟠 High
- **Arquivo(s):** `src/git/merge.rs:129-146` (`choose_latest`); origem do timestamp em `secrets_lock.rs:190-198`

**Descrição.** O vencedor do merge é escolhido pelo campo plaintext `updated_at`, que não é coberto por nenhuma assinatura/AAD e é totalmente controlável pelo atacante.

**Cenário de ataque/falha.** Atacante replaya um ciphertext antigo (vazado) com timestamp futuro → ele vence e vira o valor corrente; ou força seu valor por cima do valor mais novo de um colega. Combinado com K6, é abençoado silenciosamente.

**Correção.** Vincular `updated_at` + `id`/`name`/`data` em dados autenticados (AAD ou envelope de registro assinado); ou usar contadores de versão monotônicos por secret em vez de relógio de parede.

---

#### H3. Injeção de recipient via merge do vault → chave concedida no próximo rotate (escalada de privilégio silenciosa)

- **Severidade:** 🟠 High
- **Arquivo(s):** `src/git/merge.rs:192-226` (`merge_recipients`); sink em `src/main.rs:798` (`rewrap_recipients`)

**Descrição.** O merge absorve entradas de recipients do `theirs` não-confiável sem nenhuma prova de autorização.

**Cenário de ataque/falha.** Um colega revogado/de baixo privilégio faz push de um `vault.toml` adicionando sua própria pubkey; a vítima mescla; o próximo `dl rotate`/revoke envolve a chave do projeto para todos os recipients, incluindo o injetado → o atacante recupera acesso total silenciosamente.

**Correção.** Exigir que concessões de recipient sejam individualmente assinadas por uma chave admin autorizada e verificar essa assinatura durante o merge; nunca absorver recipients não assinados.

---

#### H4. Log de auditoria não é tamper-evident na config padrão (forjável) + truncamento de cauda indetectável

- **Severidade:** 🟠 High
- **Arquivo(s):** `src/audit/log.rs:301-315` (`sign_entry_best_effort`), `src/audit/verify.rs:12-68`

**Descrição.** (a) A assinatura é best-effort: identidades são por padrão CRIPTOGRAFADAS por passphrase, e identidades criptografadas nunca assinam → entradas escritas como `("anonymous","")`. `verify_log` (não-strict = padrão) as aceita apenas com um warning. `compute_entry_hash` é SHA-256 sem chave sobre campos públicos → qualquer um com escrita no FS reescreve a cadeia inteira de forma auto-consistente. Usuários conscientes de segurança (chave protegida por passphrase) recebem o log MAIS FRACO. (b) Não há compromisso de comprimento/cabeça → deletar as últimas N entradas ainda verifica limpo (tail rollback).

**Cenário de ataque/falha.** Atacante com acesso ao filesystem reescreve ou trunca o log de auditoria sem detecção, apagando os rastros de qualquer ataque anterior (ex.: K1–K6, H1–H3).

**Correção.** Tornar `--strict` o padrão e sair com código não-zero em qualquer entrada anônima; prover um caminho de assinatura em memória no momento do unlock para que identidades criptografadas ainda assinem (ou uma chave de auditoria no keyring do SO); armazenar uma marca d'água monotônica assinada (contagem + head hash) em metadata assinada e rejeitar um log mais curto.

---

#### H5. DEK em plaintext persistido em disco (cache de sessão)

- **Severidade:** 🟠 High
- **Arquivo(s):** `src/storage/cache.rs:112-163` (escrita), `src/storage/cache.rs:32-38` (TTL, máx. 3600s)

**Descrição.** O DEK bruto do projeto é gravado em base64 em `~/.lock/run/sessions/<uuid8>/sessions.toml`, protegido apenas por permissão 0600. Entradas expiradas só são deletadas na próxima leitura → se o `dl` nunca mais rodar, a chave persiste indefinidamente (e em backups/snapshots/swap). TTL de até 1h via `DOTLOCK_CACHE_TTL`.

**Cenário de ataque/falha.** Qualquer processo com o mesmo uid (dependência comprometida, filho de `dl run`, job de backup) lê a chave sem nenhuma criptografia, contornando inteiramente Argon2id/RSA.

**Correção.** Preferir keyring do SO / agente somente-memória (estilo ssh-agent); se o cache em arquivo permanecer, envolvê-lo sob uma chave vinculada à máquina/sessão, encurtar o TTL padrão, deletar+shred na saída do processo, zeroizar após o parse.

---

#### H6. `HOME` não definido → chave privada + cache do DEK caem no diretório commitado `./.lock/`

- **Severidade:** 🟠 High
- **Arquivo(s):** `src/storage/identity.rs:34-54`, `src/storage/cache.rs:55-75`, `src/audit/log.rs:317-337`

**Descrição.** Todos fazem fallback para `./.lock` quando `HOME`/`DOTLOCK_*` não estão definidos (cron, containers, systemd). O `identity.pem` (chave privada RSA) e o cache plaintext do DEK então caem dentro do diretório que os usuários commitam/compartilham.

**Cenário de ataque/falha.** Um job de CI/cron sem `HOME` grava a chave privada e o DEK dentro do repositório; o próximo commit/push vaza tudo para todos com acesso de leitura ao repo.

**Correção.** Falhar duro com erro claro quando nenhum home/config dir resolver; usar `dirs`/XDG. Nunca escrever material de chave no CWD.

---

### TIER 2 — MEDIUM: hardening

---

#### M1. Sem lock inter-processo no par do vault

- **Severidade:** 🟡 Medium · **Arquivo(s):** mutadores de `src/storage/secrets_lock.rs`; padrão a reutilizar em `src/audit/log.rs:97-142`

**Descrição/falha.** `dl set` concorrentes causam lost updates ou falso `TamperedSecretsFile`.
**Correção.** Reutilizar o padrão `AuditLock` (`audit/log.rs:97-142`) ao redor do read-modify-write do vault.

---

#### M2. Metadata do `vault.toml` não autenticada; checagem de tamper de recipients limitados confia em plaintext gravável pelo atacante

- **Severidade:** 🟡 Medium · **Arquivo(s):** `src/crypto/integrity.rs:110-128`, `src/storage/unlock_file.rs:117-121`

**Descrição/falha.** Recipients limitados verificam integridade contra o campo plaintext `secrets_hash_sha256_b64`, que o atacante pode reescrever junto com o conteúdo.
**Correção.** Aplicar MAC/assinatura sobre toda a metadata sob uma subchave derivada da KEK.

---

#### M3. Sem proteção contra rollback; `kek_version` não vinculado no AAD do DEK envolvido

- **Severidade:** 🟡 Medium · **Arquivo(s):** `src/crypto/dek.rs:33,56`

**Descrição/falha.** Downgrade para vault/KEK antigos passa despercebido.
**Correção.** Adicionar `kek_version` + contador monotônico ao AAD; o unlock recusa retroceder.

---

#### M4. `secret_cipher.rs` não usa AAD → troca de ciphertexts sob a mesma chave (secrets legados DEK-direto)

- **Severidade:** 🟡 Medium · **Arquivo(s):** `src/crypto/secret_cipher.rs:30-74`

**Descrição/falha.** `DB_PASSWORD` recebe silenciosamente o valor de `API_KEY` e passa no AEAD.
**Correção.** Adicionar o `id` do secret (+`name`) como AAD.

---

#### M5. TOCTOU de symlink (check→open) em `secure_fs`; leitura de pubkey sem checagem de symlink

- **Severidade:** 🟡 Medium · **Arquivo(s):** `src/storage/secure_fs.rs:81-128` (lado de leitura + componentes de `ensure_dir`), `src/storage/shared_access.rs:201`

**Descrição/falha.** Janela de corrida entre a verificação de symlink e o open permite redirecionar leituras/escritas.
**Correção.** Usar `O_NOFOLLOW`/`openat`.

---

#### M6. Janela de permissão de diretório em `ensure_dir`

- **Severidade:** 🟡 Medium · **Arquivo(s):** `src/storage/secure_fs.rs:66-73`

**Descrição/falha.** Diretório criado com umask padrão e `chmod 0700` só depois — janela de exposição.
**Correção.** Usar `DirBuilder::mode(0o700)`.

---

#### M7. Hardening de providers: TOCTOU hash→exec, path traversal no nome, checagens de diretório incompletas, provider não pinado

- **Severidade:** 🟡 Medium · **Arquivo(s):** `src/providers/mod.rs:33-48,198-260`

**Descrição/falha.** (a) TOCTOU entre verificação do hash e exec (usar open+fexecve no mesmo fd); (b) NOME do provider permite path traversal (`../bin/sh`) — validar `^[a-z0-9][a-z0-9_-]*$`; (c) checagem de diretório ignora group-writable e ownership; (d) provider não pinado (padrão) = execução arbitrária do primeiro match no PATH.
**Correção.** Exigir pin sha256 + checagem de owner; corrigir os quatro pontos acima.

---

#### M8. Valor de secret em argv (`dl set NAME value`) e vazamento em log de `dl run`

- **Severidade:** 🟡 Medium · **Arquivo(s):** `src/main.rs:148-159,522-526`, `src/runtime/mod.rs:36`, `src/audit/mod.rs:67-83`

**Descrição/falha.** Valor visível em `ps`/`/proc`/histórico do shell; secret em `dl run tool --token X` logado sem redação (flags separadas por espaço não cobertas por `sanitize_command`).
**Correção.** Adicionar `--stdin`/prompt sem eco; estender `sanitize_command` para flags com valor separado por espaço.

---

#### M9. Windows: nenhuma restrição de permissão de arquivo

- **Severidade:** 🟡 Medium · **Arquivo(s):** `src/storage/secure_fs.rs`, `src/audit/log.rs:82-92` (todos os blocos `#[cfg(unix)]`)

**Descrição/falha.** Em Windows, nenhum equivalente de 0600/0700 é aplicado.
**Correção.** Definir DACLs restritivas ou documentar a lacuna explicitamente.

---

### TIER 3 — LOW / INFO

---

#### L1. Passphrases + plaintext de secrets descriptografados em `String` não zeroizada

- **Severidade:** 🔵 Low · **Arquivo(s):** `src/crypto/mod.rs:156-217`, `src/storage/unlock_file.rs:94-103`, `src/crypto/secret_cipher.rs:55-74`

As chaves SÃO zeroizadas, mas passphrases e plaintexts não. **Correção:** envolver em `Zeroizing<String>`/`secrecy`.

---

#### L2. Viés de módulo no gerador de senhas

- **Severidade:** 🔵 Low · **Arquivo(s):** `src/crypto/passgen.rs:8-23`

`256 % 74 = 34` → os primeiros 34 caracteres são ~33% mais prováveis. **Correção:** rejection sampling.

---

#### L3. Erro do serde pode ecoar metadata descriptografada de secret dinâmico numa string de erro

- **Severidade:** 🔵 Low · **Arquivo(s):** `src/storage/secrets_lock.rs:686-688`

**Correção:** retornar um erro de parse genérico.

---

#### L4. Log de auditoria: uma linha final truncada torna o log INTEIRO ilegível; sem fsync após `writeln!`

- **Severidade:** 🔵 Low · **Arquivo(s):** `src/audit/log.rs:54-95,160-178`

Erro rígido por linha derruba a leitura completa. **Correção:** pular apenas a linha final defeituosa; fsync após escrita.

---

#### L5. Sem confirmação em operações destrutivas (`unset`, `rotate`, `revoke`)

- **Severidade:** 🔵 Low

**Correção:** adicionar `--yes` + confirmação em TTY.

---

#### L6. `dl export` escreve `.env` em plaintext sem adicioná-lo ao `.gitignore`

- **Severidade:** 🔵 Low · **Arquivo(s):** `src/main.rs:634-674`, `src/storage/env_file.rs:65-67`

O próprio `.gitignore` do repositório não cobre `.env`. **Correção:** warning + checagem do gitignore pós-export.

---

#### L7. `dl get`/`dl list` em TTY renderizam secrets/nomes na tela (scrollback)

- **Severidade:** 🔵 Low

**Correção:** considerar mascaramento por padrão.

---

#### L8. Comparações não constant-time em hashes (públicos, não secretos)

- **Severidade:** ⚪ Info

Apenas informacional — os valores comparados não são secretos.

---

## Dependências

| Crate | Versão | Advisory | Severidade | Detalhes |
|---|---|---|---|---|
| `rsa` | 0.9.10 | **RUSTSEC-2023-0071** (Marvin timing side-channel) | CVSS 5.9, **sem fix upstream** | Usado em `unwrap_dek_with_private_key` (modo share). Mitigação: documentar o risco; considerar migrar o wrapping de identidade para age/X25519 (`crypto_box`) e eliminar RSA por completo. |
| `anyhow` | 1.0.102 | **RUSTSEC-2026-0190** (`downcast_mut` unsound) | Bump disponível | Atualizar. (Ver também A4 — anyhow é dispensável no projeto.) |
| `fxhash` | transitiva | não mantido (unmaintained) | Info | Dependência transitiva; monitorar/substituir na cadeia. |
| `spin` | 0.9.8 (transitiva) | crate **yanked** | Info | Dependência transitiva yanked no crates.io. |

**Recomendação de processo:** adicionar `cargo audit`/`cargo deny` ao CI para detectar regressões de supply chain automaticamente.

---

## Arquitetura e Qualidade

#### A1. `main.rs` é um god-file de 1184 linhas
Definições clap + `dispatch()` de 500 linhas + orquestração de rotação + reencrypt + renderização de tabela, tudo junto. Não existe camada de aplicação/casos-de-uso entre a CLI e storage/crypto.

#### A2. Domínio anêmico
`domain/model.rs` contém apenas `DotLockResult`/`Alg`/`DataEncrypted` (não usado). As entidades reais (`SecretRecord`, `VaultKeyMetadata`, `VaultRecipient`, `VaultConfig`, `DynamicSecretMetadata`) vivem em `storage`/`crypto`, misturadas com I/O TOML e regras de negócio. As regras centrais são intestáveis sem o filesystem.

#### A3. Boilerplate de upsert duplicado ×3 (+ uma 4ª cópia morta)
`upsert_plain_secret`/`upsert_many`/`upsert_dynamic_secret` (~25-30 linhas cada) + `upsert_secret` morto (`#[allow(dead_code)]`, sem SDK wrapping). Um fix em um não alcança os outros — diretamente relevante para K1/K3. **Correção:** extrair um núcleo `upsert_record` + `persist` fino.

#### A4. `anyhow` usado apenas em `crypto/{kdf,dek,kek}.rs` e stringificado na borda
Via `map_err(|e| Crypto(e.to_string()))` → `Error::source()` nunca é populado. **Correção:** remover anyhow; thiserror local.

#### A5. Renderizador de tabela duplicado ×3
`src/utils.rs:127-184`, `src/main.rs:1048-1097`, `src/storage/unlock_file.rs:128-178`. **Correção:** um `render_table(headers, rows)` genérico.

#### A6. `vault.toml` relido 5× por comando
(unlock, leitura de cache, escrita de cache, prepare_write, upsert) + mais 2× para o nome do cache-dir. **Correção:** introduzir `VaultContext { metadata, dek }` construído uma vez e propagado.

#### A7. `[u8;32]` cru para DEK/SDK passado por toda parte
**Correção:** newtypes `ProjectKey`/`SecretDek` tornam confusões DEK/SDK (a raiz do K1) erros de compilação.

#### A8. Testes: 39 unitários, todos tocam o FS real via temp dirs
Sem trait de storage em memória, sem e2e via `assert_cmd` (apenas testes de parsing de aliases do clap). **Correção:** trait de storage + e2e no nível do binário (init→set→get→export→run).

#### A9. Nomenclatura enganosa
`wrapped_sdks_under_kek` é envolvido sob o **DEK**, e `dl rotate` rotaciona o **DEK**, não apenas a KEK — essa confusão de nomes plausivelmente causou o K1. **Correção:** renomear.

#### A10. clippy: 7 warnings
`unnecessary_lazy_evaluations` ×3 em `secrets_lock.rs:224,543,618`; `items_after_test_module` em `cache.rs:166`; `needless_borrow`. Limpeza de custo zero.

---

## Lacunas de Funcionalidade

(comparativo com dotenvx / sops / doppler)

#### FG1. Sem saída `--json`/machine-readable em nenhum comando
(`list`/`get`/`share list`/`audit show`) → difícil de scriptar/usar em CI.

#### FG2. Sem unlock não-interativo/CI
Não há env var / `--password-stdin` / `--password-file`; o prompt do `inquire` é o único caminho → `dl run`/`dl get` travam ou falham em CI headless, a menos que o cache de 30s esteja quente.

#### FG3. Sem multi-ambiente de primeira classe (dev/staging/prod)
Projeto/env fixados no `dl init`; cada ambiente exige um vault separado. **Sugestão:** `config`/troca de env estilo doppler.

#### FG4. Sem `dl exec` em forma shell / fallback `--env-file`
Necessário para migração gradual a partir de `.env`/dotenvx.

#### FG5. Rotação é manual (+ ratchet por contagem de escritas)
Sem agendamento / `dl rotate --if-due`.

#### FG6. Sem `dl repair` para recuperar um vault em `TamperedSecretsFile`
Necessário dado K3/K4/K6.

#### FG7. (Ponto forte a manter/destacar) Merge driver git nativo para arquivos criptografados
Um diferencial real frente a doppler/dotenvx/sops — corrigir K2/K6/H2/H3 sem perder a capacidade.

---

## Pontos Fortes (não regredir)

- **Argon2id 64MiB / t=3 / p=1** — acima das recomendações OWASP; salts frescos de 16 bytes, sem reuso.
- **XChaCha20-Poly1305** com nonces aleatórios frescos de 24 bytes por operação (espaço de 192 bits, sem reuso/contador).
- **RSA-3072 OAEP-SHA256** para wrapping + **RSA-PSS** (blinded) para assinaturas; nenhum PKCS#1v1.5.
- Chave privada **PKCS#8 criptografada com scrypt** (n=32768).
- **Envelope SDK por secret** limita o raio de dano + previne troca de ciphertext entre registros (daqui em diante).
- **Escritas atômicas de arquivo único** (temp com O_EXCL + fsync + rename, temp limpo em erro).
- **Arquivos 0600 / diretórios 0700 desde a criação** (mode no open, sem TOCTOU de chmod-depois no destino).
- **Material de chave zeroizado** (DEK/KEK/master).
- **Nenhum exec via shell** em lugar algum (arrays de argv) → sem injeção de metacaracteres.
- **Sandbox de provider:** pin sha256, caps de saída de 64KiB/16KiB, timeout+kill, rejeição de diretório world-writable.
- **Nenhum `unwrap`/`expect`/`panic` em caminhos alcançáveis por atacante** (todos em `#[cfg(test)]`).
- **`.lock/` no gitignore** — nada secreto commitado.
- **Remoção de ACL (`dl share allow --remove`) faz rotação real de SDK.**
- **`ensure_vault_clean` bloqueia `dl sync` com árvore suja; sync só faz fast-forward.**
