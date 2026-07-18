# SPEC — Fase 0: Correções críticas (K1–K6)

Escopo: os seis bugs Tier 0 do relatório consolidado. Todos envolvem perda de dados permanente, quebra da garantia de revogação ou corrupção da integridade compartilhada. Cada item entra com teste de regressão que **falha no código atual**.

Contexto de arquitetura relevante: hierarquia de chaves password → Argon2id master key → HKDF KEK → project DEK → SDKs por segredo wrapped sob o DEK (campo `wrapped_sdks_under_kek` no `vault.toml` — nome enganoso, ver A9). Par de arquivos do vault: `.lock/vault.toml` (metadata) + `.lock/secrets.lock` (registros cifrados). Hash de integridade do `secrets.lock` guardado no `vault.toml`, cifrado sob o DEK.

Ordem sugerida de implementação: **primeiro a primitiva transacional (seção ao final) → K4 → K3 → K1 → K5 → K2 → K6**. K4/K3 estabelecem a fundação de atomicidade que K1 usa; K2/K6 são o bloco do merge driver e devem ser feitos juntos.

---

## K1. `dl share revoke` quebrado para vaults v5+ — revogado mantém acesso

**Problema.** `reencrypt_secret` (`src/main.rs:974-985`) descriptografa cada registro com o DEK bruto do projeto, mas desde o vault v5 cada segredo é cifrado sob um SDK por segredo (wrapped em `metadata.wrapped_sdks_under_kek`). A descriptografia falha AEAD, o handler de Revoke (`src/main.rs:784-808`) aborta **antes** de `save_vault_metadata`, e o `wrapped_dek_b64`/`wrapped_sdks` do revogado permanecem no `vault.toml` compartilhado. Mesmo que "sucedesse", `wrapped_sdks_under_kek` nunca é re-wrapped para o novo DEK → vault ficaria indecifrável.

**Arquivos/funções a tocar.**
- `src/main.rs:784-808` — handler do subcomando Revoke.
- `src/main.rs:974-985` — `reencrypt_secret` (remover ou reescrever; hoje é o caminho errado).
- `src/storage/vault_file.rs:54-93` — `rotate_kek_wrapping` (caminho CORRETO já existente; reusar).

**Abordagem de correção.**
1. Eliminar o uso de `reencrypt_secret` no fluxo de revoke. O modelo correto não é re-cifrar registros com o DEK: os registros são cifrados sob SDKs; o que precisa mudar de dono é o **wrapping** dos SDKs e do DEK.
2. Fluxo de revoke reescrito, espelhando `rotate_kek_wrapping` (`src/storage/vault_file.rs:54-93`):
   a. Unlock com DEK antigo (full access obrigatório).
   b. Gerar DEK novo.
   c. Para cada entrada em `wrapped_sdks_under_kek`: unwrap do SDK sob o DEK antigo → rewrap sob o DEK novo. (Os ciphertexts em `secrets.lock` **não mudam** — continuam sob os mesmos SDKs.)
   d. Remover o recipient revogado de `metadata.recipients`.
   e. Para cada recipient remanescente: rewrap do DEK novo sob a pubkey dele (`rewrap_recipients`, sink em `src/main.rs:798`) e regravar seus `wrapped_sdks` conforme a ACL.
   f. Recomputar o hash de integridade do `secrets.lock` e cifrá-lo sob o DEK **novo** (`build_encrypted_hash_fields`), no MESMO objeto de metadata.
   g. Uma única chamada a `save_vault_metadata` (via primitiva transacional, ver seção final) commit tudo atomicamente.
3. Nota: revogação de wrapping não remove acesso ao histórico git — o revogado pode ainda decifrar ciphertexts antigos que já possuía. Como os SDKs são re-wrapped mas os ciphertexts não mudam, documentar que `dl share revoke` deve recomendar `dl rotate` dos valores sensíveis em seguida (ou oferecer `--rotate-values` futuro). Isso é limitação criptográfica, não bug.

**Teste de regressão.**
- Integração (temp dir, vault real): `init` → `set A=1; set B=2` (caminho normal, gera vault v5 com SDKs) → `share add` de um segundo identity → `share revoke` desse identity → asserts: (1) comando sai com sucesso; (2) `vault.toml` não contém mais `wrapped_dek_b64`/`wrapped_sdks` do revogado; (3) `dl get A` pelo owner retorna `1` (vault não brickou); (4) unlock com a identity revogada falha; (5) `verify_secrets_integrity` passa.
- Este teste falha hoje já no assert (1) — o comando aborta com erro AEAD.

**Riscos/efeitos colaterais.** Revoke passa a rotacionar o DEK (comportamento novo e correto) — sessões em cache com DEK antigo ficam inválidas; invalidar o cache de sessão (`~/.lock/run/sessions/`) do projeto no fim do revoke. Se `reencrypt_secret` for usado em outro fluxo, auditar antes de remover (grep por chamadas).

---

## K2. Merge driver orfana SDKs — segredo mergeado fica indecifrável para sempre

**Problema.** O merge de `secrets.lock` une registros, mas `merge_metadata` (`src/git/merge.rs:160-226`, com `merge_vault_metadata`/`merge_recipients`) só reconcilia `project_uuid`/`kek_version`/`version`/`recipients` — nunca mescla `wrapped_sdks_under_kek` nem adiciona entradas faltantes aos `wrapped_sdks` de um recipient existente. Segredo criado só em `theirs` perde seu wrapping (o merge parte de `ours`); depois, `secret_sdk_from_project_key` não encontra nada, cai no fallback `.unwrap_or(*dek)`, AEAD falha → segredo perdido.

**Arquivos/funções a tocar.**
- `src/git/merge.rs:160-226` — `merge_vault_metadata`, `merge_metadata`, `merge_recipients`.
- `src/git/merge.rs:41-57` — `merge_secrets_lock` (coordenação com K6).
- Ponto do fallback perigoso: `secret_sdk_from_project_key` com `.unwrap_or(*dek)` (secrets_lock) — ver passo 4.

**Abordagem de correção.**
1. Dirigir os merges de `secrets.lock` e `vault.toml` por um **único passe coordenado**: primeiro computar o conjunto de secret ids resultante do merge de registros; depois construir o `wrapped_sdks_under_kek` mergeado como união por secret id (`ours` ∪ `theirs`; em conflito no mesmo id, alinhar com o registro vencedor de `choose_latest` — o wrapping deve vir do mesmo lado que o ciphertext vencedor, senão SDK e ciphertext divergem).
2. Mesclar `wrapped_sdks` por recipient: para cada recipient presente no resultado, união por secret id das entradas de `ours` e `theirs` (mesma regra de desempate do passo 1).
3. Invariante pós-merge, verificada antes de gravar: **todo secret id presente no `secrets.lock` mergeado tem entrada em `wrapped_sdks_under_kek`**. Se violada, falhar o merge com conflito explícito (exit code de conflito do merge driver) em vez de gravar um vault órfão.
4. Endurecer o fallback: trocar `.unwrap_or(*dek)` em `secret_sdk_from_project_key` por erro explícito (`Error::MissingSecretKeyWrapping { id }`) quando o registro é v5+ — silenciar isso foi o que transformou o bug em "perda permanente" em vez de erro diagnóstico. Manter o fallback para registros legados pré-v5 (DEK-direct), identificados por versão do registro.

**Teste de regressão.**
- Teste de merge de três vias (padrão dos testes existentes de `git/merge.rs`): base com segredo A; branch `ours` adiciona B; branch `theirs` adiciona C (ambos via caminho real de `upsert_plain_secret` para gerar SDKs). Rodar o merge driver sobre os pares (base/ours/theirs de `secrets.lock` E de `vault.toml`). Asserts: os 3 ids existem no `secrets.lock` mergeado; os 3 têm entrada em `wrapped_sdks_under_kek`; decifrar A, B e C com o DEK funciona.
- Segundo teste: mesmo id modificado dos dois lados — o SDK wrapping resultante corresponde ao registro vencedor.

**Riscos/efeitos colaterais.** O merge driver passa a ler/escrever `vault.toml` e `secrets.lock` em conjunto — verificar como o git invoca o driver (um arquivo por vez): a coordenação exige que o driver do `secrets.lock` localize os três estágios do `vault.toml` (via `git checkout-index`/stages ou config do driver para ambos os paths). Se a coordenação plena for inviável no protocolo do driver, o mínimo aceitável é: união de `wrapped_sdks_under_kek` no merge do `vault.toml` + invariante do passo 3 checada no primeiro `dl` pós-merge com instrução de recuperação.

---

## K3. Par `secrets.lock` + `vault.toml` não é transacional — crash = perda ou lockout permanente

**Problema.** Cada gravação individual é atômica (temp O_EXCL + fsync + rename), mas o PAR não: crash entre a gravação nova do `secrets.lock` e a do `vault.toml` (com novo SDK wrapping + hash re-cifrado) deixa (a) SDK do segredo novo perdido → ciphertext indecifrável, e/ou (b) hash stale → próximo unlock dá `TamperedSecretsFile` sem recuperação.

**Arquivos/funções a tocar.**
- `src/storage/secrets_lock.rs` — todos os mutators: `upsert_plain_secret:206`, `upsert_many:519`, `upsert_dynamic_secret:601`, `migrate_all_secrets_to_envelope:311`, `rotate_secret_sdks_after_acl_removal:357`, `remove_secret_by_name:712`.
- `src/main.rs:930-936` — gravação pós-rotação.
- Novo módulo: `src/storage/vault_txn.rs` (a primitiva da seção final).

**Abordagem de correção.**
1. Implementar a primitiva `commit_vault_pair` (seção "Padrão de escrita transacional" abaixo).
2. Refatorar cada mutator para: construir os DOIS estados finais em memória (bytes do `secrets.lock` novo + `VaultMetadata` novo, já com SDK wrapping e `secrets_hash_*` recomputado sob o DEK vigente) e chamar `commit_vault_pair` uma única vez. Nenhum mutator grava arquivo diretamente.
3. Ordem interna da primitiva garante a semântica pedida no relatório: metadata (hash+SDK) commitada de forma que nunca exista `secrets.lock` novo sem seu SDK/hash correspondente recuperável.
4. Aproveitar para extrair o núcleo comum dos upserts (antecipação de A3): os três `upsert_*` compartilham `upsert_record(record, sdk) -> (new_lock_bytes, new_metadata)`; remover o quarto morto `upsert_secret` (`#[allow(dead_code)]`, sem SDK wrapping — é uma armadilha).

**Teste de regressão.**
- Fault injection por hook de teste: adicionar em `commit_vault_pair` um ponto de falha controlado (`#[cfg(test)]` hook ou env var `DOTLOCK_TEST_CRASH_AFTER=first_write`) que aborta o processo após a primeira gravação física. Teste com `assert_cmd`/subprocess: `set` com crash injetado → novo processo `dl get` → ou o segredo antigo está intacto e o novo ausente (rollback limpo), ou ambos consistentes (commit completo); **nunca** `TamperedSecretsFile` nem AEAD failure. Repetir com o crash após a segunda gravação parcial (journal presente) e verificar que a recuperação no próximo `dl` completa a transação.
- Teste unitário da primitiva: temp dir, simular journal órfão das duas formas (só passo 1 feito; passo 1+2 feitos) e verificar `recover_pending`.

**Riscos/efeitos colaterais.** Todos os caminhos de escrita mudam de forma — é a mudança de maior raio da fase; fazê-la primeiro e rebasear K1/K4/K5 sobre ela. O journal adiciona um arquivo em `.lock/` — deve ser gitignorado (o diretório já é) e limpo em toda recuperação.

---

## K4. Janela de crash na rotação bricka o vault

**Problema.** `rotate_project_key_wrapping` (`src/main.rs:916-936`) grava o `vault.toml` com o DEK novo wrapped, e só numa SEGUNDA gravação (`save_rotated_project_key`) re-cifra o hash de integridade sob o DEK novo — `rotate_kek_wrapping` (`src/storage/vault_file.rs:54-93`) não toca `secrets_hash_*`. Crash entre as duas: wrapped_dek é o novo, mas o hash continua cifrado sob o DEK antigo (irrecuperável) → `TamperedSecretsFile` permanente. Também disparado silenciosamente pelo auto-ratchet `prepare_project_key_for_write` (`src/main.rs:901-914`) em escritas comuns.

**Arquivos/funções a tocar.**
- `src/main.rs:916-936` — `rotate_project_key_wrapping` + `save_rotated_project_key` (fundir).
- `src/main.rs:901-914` — `prepare_project_key_for_write` (usa o caminho fundido).
- `src/storage/vault_file.rs:54-93` — `rotate_kek_wrapping`: passar a receber/retornar também os campos `secrets_hash_*` re-cifrados, ou retornar a metadata mutada para o caller completar antes do save.

**Abordagem de correção.**
1. Mudar a assinatura de `rotate_kek_wrapping` para operar sobre um `&mut VaultMetadata` completo e, além de re-wrappar DEK e SDKs, **recomputar `secrets_hash_*` cifrado sob o DEK novo no mesmo objeto** (o conteúdo do `secrets.lock` não muda na rotação; só a cifra do hash muda — usar `build_encrypted_hash_fields` com o DEK novo sobre o hash corrente).
2. Um único `save_vault_metadata` (via `commit_vault_pair`; aqui só o `vault.toml` muda, o `secrets.lock` entra inalterado — a primitiva aceita "pair com um lado no-op").
3. Deletar `save_rotated_project_key` como passo separado; `prepare_project_key_for_write` passa a devolver a metadata pronta para o commit único do mutator que o chamou (a rotação-ratchet e o upsert commitam JUNTOS, numa transação só).

**Teste de regressão.**
- Unitário: chamar a rotação com hook de crash entre as (antigas) duas gravações — após o fix esse ponto deixa de existir; o teste vira: rotação com crash injetado dentro de `commit_vault_pair` → reabrir → unlock funciona e `verify_secrets_integrity` passa (com DEK antigo OU novo, conforme o commit tenha ou não sido concluído — nunca estado misto).
- Integração do ratchet: forçar `prepare_project_key_for_write` a disparar (contador de escritas no limiar) num `dl set`, com crash injetado; verificar recuperação.

**Riscos/efeitos colaterais.** Assinatura de `rotate_kek_wrapping` muda — atualizar todos os callers (rotate explícito, ratchet, e o revoke reescrito de K1, que reusa exatamente este caminho). Baixo risco de formato: nada muda em disco, só a ordem/agrupamento das gravações.

---

## K5. Recipient limitado deleta segredos e corrompe a integridade de todos

**Problema.** Os upserts chamam `reject_limited_identity_write`, mas `remove_secret_by_name` (`src/storage/secrets_lock.rs:712-745`, usado por `dl unset`) não. O unlock de recipient limitado devolve um DEK dummy `[0u8;32]` (`src/storage/unlock_file.rs:105-126`), que flui para `build_encrypted_hash_fields` → hash de integridade cifrado sob a chave zero → próximo unlock full-access falha AEAD → `TamperedSecretsFile` para o time inteiro.

**Arquivos/funções a tocar.**
- `src/storage/secrets_lock.rs:712-745` — `remove_secret_by_name`: adicionar a checagem.
- `src/storage/unlock_file.rs:105-126` — origem do DEK dummy: trocar o tipo de retorno.
- `src/main.rs:567-576` — call site do unset.
- `build_encrypted_hash_fields` — guarda defensiva.

**Abordagem de correção (defesa em três camadas).**
1. Imediato: chamar `reject_limited_identity_write` em `remove_secret_by_name` e auditar (grep) TODOS os caminhos mutantes por checagem equivalente — a lista de K3 é o checklist.
2. Estrutural: eliminar o DEK mágico zero. O unlock passa a devolver um enum, p.ex. `UnlockAccess::Full(ProjectKey)` / `UnlockAccess::Limited { readable_sdks: ... }` — o tipo torna impossível um caminho de escrita receber "um DEK" de identidade limitada. (Sinergia direta com o newtype `ProjectKey` de A7; introduzir o newtype aqui já.)
3. Cinto e suspensório: `build_encrypted_hash_fields` rejeita com erro se a chave for toda-zero.

**Teste de regressão.**
- Integração: vault com owner + recipient limitado (read-only de um subset). Com a identidade limitada: `dl unset NAME` → deve falhar com erro de permissão; `secrets.lock` e `vault.toml` intactos (comparar bytes/mtime). Depois, unlock full-access do owner → `verify_secrets_integrity` passa.
- Unitário: `build_encrypted_hash_fields` com chave `[0u8;32]` retorna erro.

**Riscos/efeitos colaterais.** A mudança do tipo de retorno do unlock (camada 2) toca todos os call sites de unlock — mecânica mas ampla; se apertar o prazo, entregar camadas 1+3 nesta fase e a 2 no início da Fase 2 (registrado como dívida). Camada 1 sozinha já fecha o vetor `dl unset`.

---

## K6. Merge driver re-abençoa conteúdo não confiável ou pula o hash silenciosamente

**Problema.** Após mesclar `theirs` (não confiável), `merge_secrets_lock` (`src/git/merge.rs:41-57`) recomputa o hash de integridade com o DEK do usuário LOCAL — "lavando" qualquer conteúdo do merge (inclusive replays) como válido. E quando não há DEK (git pull não-interativo, CI, cache de 30s expirado), o refresh é pulado com `.ok()` → hash stale → falso `TamperedSecretsFile` no próximo `dl`.

**Arquivos/funções a tocar.**
- `src/git/merge.rs:41-57` — `merge_secrets_lock`.
- Novo estado "merge pendente de reconciliação" (marker em `.lock/`, p.ex. `.lock/pending-merge`) + fluxo interativo no unlock (`src/main.rs` dispatch / caminho de unlock).

**Abordagem de correção.**
1. Remover o auto-refresh do hash de dentro do driver — o driver NUNCA assina conteúdo.
2. O driver, ao produzir um merge conteúdo-válido (união dos registros + invariante SDK de K2 satisfeita), grava o resultado E um marker `pending-merge` (com o hash SHA-256 público do conteúdo mergeado, para detectar adulteração posterior do próprio resultado).
3. No próximo comando `dl` interativo com unlock full-access: detectar o marker → mostrar um diff legível (segredos adicionados/alterados/removidos pelo merge — nomes e ids, não valores) → sob confirmação explícita do usuário, recomputar e re-cifrar o hash sob o DEK, remover o marker, commit via `commit_vault_pair`. Recusa → instruções para `git checkout --ours`/resolução manual.
4. "Sem DEK" deixa de ser caso silencioso por construção: o driver não precisa mais de DEK. Se o driver não conseguir sequer produzir merge conteúdo-válido (invariante de K2 violada), retornar exit code de conflito para o git deixar os markers de conflito — nunca sucesso silencioso.
5. Comandos não-interativos (`dl run` em CI) que encontram o marker: falhar com erro claro "vault has an unreconciled merge; run `dl reconcile` interactively" (o subcomando pode ser o próprio fluxo do passo 3 exposto como `dl reconcile` ou embutido no unlock).

**Teste de regressão.**
- Merge sem DEK disponível (cache limpo, env não-interativo): driver retorna sucesso de conteúdo + marker criado; `dl get` subsequente não-interativo falha com a mensagem de reconciliação (não com `TamperedSecretsFile`).
- Fluxo completo: merge → `dl` interativo (stdin scriptado confirmando) → marker removido, integridade verde, segredos de ambos os lados legíveis.
- Anti-laundering: adulterar `secrets.lock` manualmente APÓS o merge (marker presente, hash público diverge) → reconcile recusa.

**Riscos/efeitos colaterais.** UX: todo merge passa a exigir um passo interativo — é o custo correto de tamper-evidence; documentar no README e na mensagem de erro. Interação com H2/H3 (Fase 1): o diff do reconcile é o ponto natural para futuramente exibir também recipients injetados e regressões de timestamp — desenhar a função de diff pensando nessa extensão.

---

## Padrão de escrita transacional do par vault

Primitiva única e reutilizável pela qual K1, K3, K4 e K6 (e todos os mutators futuros) roteiam qualquer mudança no par `vault.toml` + `secrets.lock`.

**Local:** novo `src/storage/vault_txn.rs`.

**API proposta.**

```rust
pub struct VaultPairWrite<'a> {
    pub metadata: &'a VaultMetadata,      // estado final completo (hash + SDKs já recomputados)
    pub secrets_lock_bytes: Option<&'a [u8]>, // None = secrets.lock inalterado (ex.: rotação K4)
}

/// Commita as duas gravações como uma transação: ou ambas visíveis, ou nenhuma.
pub fn commit_vault_pair(lock_dir: &Path, write: VaultPairWrite) -> Result<(), Error>;

/// Chamada no início de todo acesso ao vault (unlock/leitura): completa ou desfaz
/// uma transação interrompida encontrada no journal.
pub fn recover_pending(lock_dir: &Path) -> Result<RecoveryOutcome, Error>;
```

**Mecanismo (journal + double temp-rename).**

1. Escrever `vault.toml.tmp` e `secrets.lock.tmp` (O_EXCL, 0600 — reusar `secure_fs`), `fsync` em ambos.
2. Escrever o journal `.lock/txn.journal` (O_EXCL) contendo: sha256 de cada temp, sha256 dos arquivos atuais (para rollback), timestamp. `fsync` do journal e `fsync` do diretório `.lock/`.
3. `rename(vault.toml.tmp → vault.toml)`; `fsync` dir.
4. `rename(secrets.lock.tmp → secrets.lock)`; `fsync` dir.
5. Remover `txn.journal`; `fsync` dir.

**Recuperação (`recover_pending`)** — se `txn.journal` existe na abertura:
- Ambos os arquivos correntes batem com os sha256 "novos" do journal → transação completou; só limpar o journal (roll-forward trivial).
- Temps ainda existem e os correntes batem com os sha256 "antigos" → crash antes do passo 3; deletar temps + journal (rollback limpo).
- Estado misto (um renomeado, outro não) → **roll-forward**: o temp remanescente ainda existe (rename não o consumiu) → completar o rename faltante, limpar journal. Se o temp faltante não existir (impossível sob o protocolo, possível sob adulteração), reportar erro dirigindo para `dl repair`.
- Journal ilegível/truncado: se os temps existem e batem entre si, tratar como pré-passo-3 (rollback); senão, erro → `dl repair`.

Ordenação semântica: como o `vault.toml` (com SDK wrapping + hash novos) é renomeado ANTES do `secrets.lock`, o único estado intermediário observável sem journal seria "metadata nova + lock antigo" — que a recuperação resolve via journal, e que, mesmo se o journal fosse perdido, nunca produz o estado fatal "ciphertext novo sem SDK" (o inverso da falha de K3 hoje).

Requisitos acessórios: integra o lock inter-processo (M1 — pode ser antecipado aqui como flock no journal path, prevenindo dois writers simultâneos); journal e temps sob `.lock/` (já gitignorado); todos os caminhos via `secure_fs` (permissões e symlink checks existentes).

**Migração:** os seis mutators de `secrets_lock.rs`, `src/main.rs:930-936` e o fluxo de revoke/rotate param de chamar gravações diretas; grep final garante que `save_vault_metadata`/gravação de `secrets.lock` fora de `vault_txn.rs` seja erro de review (idealmente: mover as funções de gravação crua para visibilidade `pub(crate)` restrita ao módulo txn).

---

## `dl repair` — spec (referenciado por FG6)

Rota de recuperação manual para vaults em `TamperedSecretsFile` causado por dessincronização hash↔conteúdo (K3/K4/K6 históricos, journals perdidos, restores de backup parciais). **Não** é bypass de tamper-evidence: exige DEK válido e confirmação explícita.

**Comando:** `dl repair [--dry-run] [--yes]`

**Fluxo.**
1. `recover_pending` primeiro — se um journal resolve o problema, terminar aí (relatar o que foi feito).
2. Unlock full-access normal (senha → DEK). Sem DEK válido, `repair` recusa — um atacante sem a senha não pode re-abençoar nada.
3. Diagnóstico, impresso sempre (e único output no `--dry-run`):
   - `secrets.lock` parseia? Quantos registros, quais ids/names (não valores).
   - Para cada registro: existe SDK em `wrapped_sdks_under_kek`? O unwrap do SDK sob o DEK funciona? O AEAD do registro abre sob o SDK?
   - O hash de integridade armazenado decifra sob o DEK? Bate com o conteúdo atual?
4. Classificação e ação (sob confirmação TTY ou `--yes`):
   - **Hash stale, todos os registros decifráveis** (caso K4 clássico): recomputar o hash do `secrets.lock` corrente, re-cifrar sob o DEK, commit via `commit_vault_pair`. Caso 100% recuperável.
   - **Registros com SDK ausente ou AEAD falho** (caso K2/K3): listar os ids irrecuperáveis; oferecer `--prune` para removê-los e reassinar o restante (perda de dados explícita e enumerada, nunca silenciosa). Sem `--prune`, apenas reportar e sair non-zero.
   - **`vault.toml` corrompido/ilegível**: fora de escopo do repair automático; instruir recuperação via git history (`git checkout <rev> -- .lock/vault.toml`) e re-rodar.
5. Toda execução de repair grava entrada no audit log (ação `repair`, ids afetados) — um repair é evento de segurança auditável.

**Testes.** (1) Vault com hash deliberadamente stale (gravado sob DEK rotacionado "perdido") → `repair` restaura, `dl get` volta a funcionar. (2) Vault com um registro sem SDK → `--dry-run` lista o id; `--prune --yes` remove só ele e o resto permanece íntegro. (3) `repair` sem senha correta falha sem modificar nada.

**Fase 0 entrega:** o caminho (1) (hash stale) + `--dry-run`, pois é a rede de segurança dos próprios fixes desta fase. Prune e polimento de UX ficam para FG6 na Fase 4.
