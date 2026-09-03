# Security Recall and Precision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que a análise encontre o que existe (o scanner interno deixa de ler lixo, e os dois scanners de segredos somam-se em vez de se excluírem), que a triagem prometida aconteça de facto (verificada no fecho, não pedida no prompt), e que o `coverage_note` seja legível em dez segundos.

**Architecture:** Nada de novo em motores. O bloco corrige o âmbito do scanner interno pelo mecanismo que o Gitleaks já usa; muda `_scan_secrets` de "um ou outro" para "ambos, unidos por fingerprint"; acrescenta a `cmd_finish` um gate que recusa `done` sem triagem; proíbe a ferramenta `Agent` **no lançamento** do job derivado, não no prompt; e guarda o `coverage_note` também como estrutura por fase, ao lado da prosa.

**Tech Stack:** Python 3.13 stdlib, bash (`bin/claude-cron`), pytest.

## Global Constraints

- **Sem dependências novas.** Nenhum motor novo, nenhum pacote Python.
- **Nenhum valor de segredo chega ao ledger, a um report ou a um log** — nem mascarado. A união de scanners toca no caminho mais sensível; toda a asserção adversarial existente tem de continuar a passar.
- **Validação viva de credenciais está FORA** — decisão do operador, 2026-09-02. Nenhuma tarefa pode introduzir um pedido de rede com um segredo.
- **`CHANGELOG.md` no MESMO commit que o código.** O `selftest` compara datas de commit de `CHANGELOG.md` e `bin/`; falha se o código for mais novo. Já apanhou este projecto uma vez.
- **Código, identificadores, docstrings, comentários e commits em INGLÊS.** Prosa de `docs/superpowers/` em pt-PT.
- **Testes, nas DUAS configurações, mais o selftest nos DOIS locales:**
  - `rtk proxy python3.13 -m pytest tests/security/ -q` (868 hoje)
  - `CC_SECURITY_ENGINES=on rtk proxy python3.13 -m pytest tests/security/ -q`
  - `rtk proxy bin/claude-cron selftest` e `rtk proxy env LC_ALL=en_US.UTF-8 bin/claude-cron selftest` (456 hoje)
- **Não tocar em `bin/security/` enquanto uma análise estiver `running`** no ledger local — o `claude-cron` no PATH é um symlink para este checkout, e a análise lê os módulos a cada verbo. Verificar com `sqlite3 data/security.db "select id,state from analysis where state='running'"` antes de começar cada tarefa que toque código.

### Como ler ficheiros neste repositório — não negociável

**`Read` para ficheiros, `rtk proxy grep` para procurar. Nunca `cat`, `head`, `sed -n` ou `grep` directos.** O hook `rtk` trunca por desenho e o seu sumarizador de pytest diz "No tests collected" em execuções com `-k`, que se lê como um passe. O pytest nativo faz o mesmo quando falta um node-id. **`python3` nesta máquina é 3.14 sem pytest — usar `python3.13`.**

### O que foi medido, e que o implementador não deve voltar a assumir

Ver a spec. Em resumo: dos 22 ficheiros que o Gitleaks "perdeu", 3 são cabeçalhos PEM sem corpo, 1 é a chave de documentação da AWS, 22 ocorrências estão em `.superpowers/` (git-ignored), 9 em `docs/`, e os 15 em código real são **o mesmo token de seed repetido** entre `seed-auth.py`, `_auth.py` e a colecção Postman. O agente da análise 10 **não triou nenhum** dos 40 achados determinísticos e lançou **6 subagentes** para o SAST; a análise 9 custou **$51,44**.

---

## File Structure

**Modificar:**
- `bin/security/secrets.py` — `SKIP_DIRS` ganha o que falta
- `bin/security/cli.py` — `_scan_secrets` (união), `cmd_finish` (gate de triagem), `_produced_by` (lista)
- `bin/security/ledger.py` — coluna aditiva `coverage` (JSON por fase), `triaged` em `finding`
- `bin/security/report.py`, `ui/security/analysis.js` e vizinhos — render do coverage estruturado
- `bin/claude-cron` — `security_derived_jobs()` passa `--disallowedTools Agent`; `security_prompt()` diz porquê
- `skills/security-analysis/SKILL.md` — Job 2 antes do Job 3; subagentes proibidos; o gate explicado
- `CHANGELOG.md` — em cada commit

**Criar:**
- `tests/security/test_recall.py` — as medições antes/depois como testes

---

### Task 1: O scanner interno deixa de ler lixo

**Files:** `bin/security/secrets.py`, `tests/security/test_secrets.py`, `tests/security/test_recall.py`

**Interfaces:** `secrets.SKIP_DIRS` é lido por `adapters.py` (12×), `deps.py`, `hygiene.py`, `ignores.py` — mudar aqui muda todos, que é o pretendido.

**O defeito, medido:** `SKIP_DIRS = {".git","node_modules","vendor","__pycache__",".venv","dist","build"}`. `.superpowers` não está lá; é git-ignored e é onde os agentes deste repositório escrevem diffs e relatórios de trabalho. No Minerva produziu 22 ocorrências de `generic_secret`. `data/logs` tem a mesma natureza. O Gitleaks recebe estes via `scope_patterns`, que **também** lê `SKIP_DIRS` — portanto a correcção num sítio serve os dois.

- [ ] **Step 1: o teste que reproduz a medição**

```python
# tests/security/test_recall.py
from security import secrets, ignores

def test_agent_workspaces_are_never_scanned(tmp_path):
    # .superpowers/ is where this repository's own agents write review diffs
    # and reports; data/logs/ is where run transcripts land. Both are
    # git-ignored, both routinely contain credential-shaped text (a captured
    # AKIA… in a review diff, a planted key in a transcript), and neither is
    # the project. Measured on Minerva: 22 generic_secret hits from
    # .superpowers/ alone, none of them a leak.
    for d in (".superpowers/sdd", "data/logs/security-x", "src"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "f.txt").write_text('password = "Zq9tRw2mXk7pLn4vBs8yHd3fGj6c"\n')
    findings, _, _ = secrets.scan_tree(tmp_path, ())
    files = {o["file"] for f in findings for o in f["occurrences"]}
    assert files == {"src/f.txt"}, files
```

- [ ] **Step 2: correr, ver falhar** (`.superpowers/sdd/f.txt` e `data/logs/...` aparecem)
- [ ] **Step 3: acrescentar a `SKIP_DIRS`** — `.superpowers`, `data/logs`, e o que mais o `gitleaks_config` do bloco 2 já excluía por medição. Com comentário a dizer **porquê e o número medido**.
- [ ] **Step 4: medir no Minerva** antes e depois, `scan_tree` directo, e pôr os dois números no relatório da tarefa. Critério: as ocorrências em `.superpowers/` vão a zero; nada em `src/`, `services/`, `scripts/` muda.
- [ ] **Step 5: suites nas duas configurações + selftest nos dois locales. Commit com CHANGELOG.**

---

### Task 2: Os dois scanners de segredos somam-se

**Files:** `bin/security/cli.py` (`_scan_secrets`), `bin/security/adapters.py` (se precisar de expor o dedup), `tests/security/test_cli.py`, `tests/security/test_recall.py`

**Interfaces:** `_scan_secrets` devolve `(findings, notes, lines, producer)`; `producer` passa a poder ser `"gitleaks+secrets"`. `_produced_by`/`diff._proven` têm de aceitar um produtor composto — **ler `diff._proven` primeiro**, porque a regra "ausência provada só por quem cunhou" tem de continuar a funcionar quando quem cunhou foram dois.

**Porquê era "um ou outro", e porquê deixa de ser:** o docstring de `_scan_secrets` diz que dois scanners dão dois fingerprints para um segredo porque nomeiam regras de forma diferente. Era verdade antes do bloco 1. Agora `taxonomy.RULE_RENAMES` mapeia `aws_access_key → aws-access-token` e cinco outros, e `secret_fingerprint` é `tipo + caminho` — portanto **depois de normalizar o tipo pelo mapa, o fingerprint é o mesmo**. Onde não há mapa (`github_token`, `slack_token`, deliberadamente), há duas identidades, e o `coverage_note` diz-o.

- [ ] **Step 1: o teste da união**

```python
def test_both_secret_scanners_run_and_their_findings_merge(tmp_path, monkeypatch):
    # One planted AWS key that both scanners see, one seed-shaped token only
    # the built-in generic rule sees. After the union there is ONE aws
    # finding (not two under two rule names) and the generic one survives.
    ...  # plant, run _scan_secrets with gitleaks present, assert:
    aws = [f for f in findings if f["rule"] == "aws-access-token"]
    assert len(aws) == 1 and set(aws[0]["seen_by"]) == {"gitleaks", "secrets"}
    assert any(f["rule"] == "generic-api-key" for f in findings)
    assert producer == "gitleaks+secrets"
```

- [ ] **Step 2: ver falhar** (hoje só o Gitleaks corre quando existe).
- [ ] **Step 3: implementar** — correr ambos; normalizar o `rule` do interno pelo `RULE_RENAMES` antes de calcular o fingerprint; unir por fingerprint, mantendo as ocorrências de ambos e um campo `seen_by`; `producer = "gitleaks+secrets"`. As **notas** dizem: quantos achados só um viu, e quais os tipos sem mapa que podem aparecer duas vezes.
- [ ] **Step 4: o teste de identidade sobre o ledger real** — um `accepted` sobre um `private-key` no ledger de desenvolvimento continua a casar depois da união (o bloco 1 migrou tudo para os nomes do Gitleaks; a união não pode desfazer isso).
- [ ] **Step 5: o teste adversarial existente** (a string injectada não aparece em lado nenhum) corre sobre o caminho da união. **Não é opcional.**
- [ ] **Step 6: medir no Minerva** — ficheiros com achados: interno só / Gitleaks só / ambos / união, antes e depois. Critério: união ≥ máximo dos dois, e zero duplicados para os seis tipos mapeados.
- [ ] **Step 7: suites, selftest, commit com CHANGELOG.**

---

### Task 3: A triagem passa a ser verificada no fecho

**Files:** `bin/security/ledger.py` (coluna `triaged`), `bin/security/cli.py` (`cmd_report_finding` marca; `cmd_finish` verifica), `tests/security/test_cli.py`, `tests/security/test_ledger.py`

**Interfaces:** `record_finding` recebe um upsert do agente sobre um fingerprint cujo `producer` é determinístico → marca `triaged=1` nessa linha. `cmd_finish --state done` conta `finding WHERE analysis_id=? AND producer NOT LIKE '%agent%' AND severity IN ('critical','high','medium') AND triaged=0`; se > 0, fecha `capped` com uma nota que **nomeia a contagem e as três primeiras**.

**Porquê no fecho e não no prompt:** a skill já pede a triagem em duas páginas. A análise 10 não triou nada. Uma instrução sem consequência é o que aconteceu; um `capped` que diz "40 achados não foram lidos" é uma consequência.

- [ ] **Step 1: testes** — (a) um re-report do agente sobre um fingerprint do Trivy marca `triaged`; (b) `finish --state done` com um `high` do Trivy não triado fecha `capped` e a nota nomeia-o; (c) com todos triados, fecha `done`; (d) `low`/`info` não triados **não** bloqueiam (o limiar é `medium`); (e) uma análise sem achados determinísticos fecha `done` sem ruído.
- [ ] **Step 2: ver falhar.** **Step 3: implementar** — coluna aditiva pelo padrão `_FINDING_COLUMNS`; a marcação em `record_finding` quando o upsert vem do agente sobre linha de outro produtor; o gate em `cmd_finish`, **antes** do `prepared` check e com a mesma forma (downgrade para `capped`, nunca recusa).
- [ ] **Step 4: o limiar é uma constante nomeada** (`TRIAGE_FLOOR = "medium"`), com o comentário a dizer que é um palpite a medir na primeira análise.
- [ ] **Step 5: suites, selftest, commit com CHANGELOG.** A entrada diz o custo de não ter isto: a análise 10 fechou `done` com 40 achados que ninguém leu.

---

### Task 4: A skill reordena os jobs e explica o gate

**Files:** `skills/security-analysis/SKILL.md`, `tests/security/test_taxonomy.py` (o teste que fixa a skill ao código)

- [ ] **Step 1:** Job 2 (triagem) passa para **antes** do Job 3 (SAST), com a razão: a triagem é barata, o SAST é caro, e o orçamento acaba — na análise 10 acabou no SAST e a triagem nunca chegou.
- [ ] **Step 2:** o gate da Task 3 explicado ao agente: o que `finish --state done` vai contar, e que `capped` com "N não triados" é o resultado de saltar o Job 2.
- [ ] **Step 3:** **subagentes proibidos, e a razão é o custo**: a análise 9 custou $51 com seis. Diz que a ferramenta `Agent` não está disponível (Task 5 garante-o) e que dividir o repositório por áreas não é a resposta — um `capped` que diz o que ficou por ver é.
- [ ] **Step 4:** o teste existente que fixa a skill ao vocabulário ganha uma asserção: a secção do Job 2 vem antes da do Job 3 no documento, e a palavra `Agent` aparece numa frase de proibição.
- [ ] **Step 5: commit com CHANGELOG** (é mudança de comportamento do agente).

---

### Task 5: A ferramenta `Agent` fecha-se no lançamento

**Files:** `bin/claude-cron` (`security_derived_jobs()`, ~linha 151–260; `security_prompt()`), `test/` (o runner shell — ver como os outros testes do job derivado estão escritos)

**Interfaces:** o job derivado já é construído em `security_derived_jobs()` e o `run_job` já lê `.allowed_tools` (linha 6482) para `--allowedTools`. **Confirmar primeiro** se o CLI do Claude aceita `--disallowedTools` (a documentação diz que sim) — se aceitar, é a via certa, porque uma *allowlist* teria de enumerar tudo o que o agente precisa e partia à primeira ferramenta nova; se não, usar `allowed_tools` com a lista completa menos `Agent`, e documentar o custo.

- [ ] **Step 1: teste shell** — o job derivado, tal como `jobs_json` o emite, carrega o campo que exclui `Agent`; e um `run_job` em modo *dry* mostra a flag nos args.
- [ ] **Step 2: implementar** em `security_derived_jobs()`, com o comentário a citar a medição ($51, 6 subagentes, 0 triagens).
- [ ] **Step 3: o prompt** (`security_prompt()`) ganha uma linha: a ferramenta não existe nesta análise, e porquê.
- [ ] **Step 4: `selftest` nos dois locales, commit com CHANGELOG.**

---

### Task 6: O `coverage_note` ganha estrutura

**Files:** `bin/security/ledger.py` (coluna `coverage` JSON, aditiva), `bin/security/cli.py` (`cmd_prepare` e `cmd_finish` escrevem-na ao lado da prosa), `bin/security/report.py`, `ui/security/analysis.js` e os outros dois que lêem `coverage_note`, `tests/security/test_report.py`, `tests/test_page_contract.py`

**O formato:**
```json
{"phases": [
  {"name": "secrets",      "status": "ran",     "by": "gitleaks+secrets", "note": "…"},
  {"name": "dependencies", "status": "ran",     "by": "trivy",            "note": "…"},
  {"name": "iac",          "status": "skipped", "by": null,               "note": "trivy is not available…"},
  {"name": "sast-prepass", "status": "warning", "by": "semgrep",          "note": "1 rule for bash…"}
]}
```

**Porquê ao lado e não em vez:** três relatórios e três ecrãs lêem `coverage_note` como texto hoje. A prosa continua a existir e continua verdadeira; a estrutura é o que a UI e o Markdown mostram **primeiro** — uma linha por fase, com o estado — e a prosa fica dobrada por baixo para quem quiser o porquê.

- [ ] **Step 1: testes** — `as_json` carrega `coverage.phases`; `as_markdown` abre com uma tabela de fases antes da prosa; a UI mostra uma linha por fase com um indicador de estado; uma análise antiga (sem a coluna) renderiza como hoje.
- [ ] **Step 2: ver falhar. Step 3: implementar** — cada `_scan_*` em `cmd_prepare` já devolve `(findings, notes, …, producer)`; passa a devolver também o `status`. `cmd_prepare` monta a lista e grava; `cmd_finish` acrescenta as suas fases (triagem, SAST do agente).
- [ ] **Step 4: `npm run build`** — `bin/static/*` são artefactos commitados e o `selftest` verifica que batem com as fontes.
- [ ] **Step 5: suites, selftest nos dois locales, commit com CHANGELOG.**

---

## Ordem e dependências

1 → 2 (a união só depois do âmbito, senão traz o lixo de volta). 3 → 4 (a skill explica um gate que tem de existir). 5 é independente. 6 é independente. **Nenhuma tarefa que toque `bin/security/` arranca com uma análise `running`.**

## Self-Review

**Cobertura da spec:** âmbito (T1), união (T2), triagem verificável (T3+T4), subagentes (T4+T5), coverage estruturado (T6). Validação viva: fora, por decisão. Alcançabilidade: é o que a triagem faz para `dependency` e a skill já o pede — a T3 torna-a obrigatória.

**O ponto frágil, assinalado:** a T2 assume que `diff._proven` sabe lidar com um produtor composto (`"gitleaks+secrets"`). Se a comparação for igualdade exacta de strings, a regra "ausência só provada por quem cunhou" parte de forma silenciosa — um achado cunhado por `"gitleaks+secrets"` nunca seria provado ausente por uma análise em que só um correu. O implementador da T2 **lê `_proven` antes de escrever uma linha** e, se for igualdade exacta, generaliza para "o produtor actual contém todos os que cunharam" e testa as três combinações.
