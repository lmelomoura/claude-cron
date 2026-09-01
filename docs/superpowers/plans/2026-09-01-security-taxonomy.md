# Security Taxonomy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dar a um achado de SAST uma identidade estável e uma classificação padrão — vocabulário fechado de `rule`, CWE e OWASP por regra, e uma renomeação de regra que não destrói o histórico nem as decisões humanas.

**Architecture:** Um módulo novo, `bin/security/taxonomy.py`, é a única fonte de verdade sobre que regras de SAST existem e a que CWE/OWASP correspondem. O `report-finding` passa a recusar uma regra fora desse mapa e a derivar `cwe`/`owasp` dela, em vez de os aceitar do agente. O ledger ganha duas colunas pelo mesmo padrão aditivo de `ALTER TABLE` guardado por `PRAGMA table_info` que já usa para `analysis`, e um mapa de renomeações reescreve fingerprints e decisões numa transacção.

**Tech Stack:** Python 3.13 (stdlib apenas — `sqlite3`, `hashlib`, `argparse`), pytest.

## Global Constraints

- **Sem dependências novas.** `bin/security/` é stdlib apenas; nada de pacotes externos.
- **O agente nunca escreve no ledger directamente** — tudo passa por `bin/security/cli.py`, que valida primeiro.
- **Nenhum valor de segredo entra no ledger, num report ou num log** — nem mascarado. Esta regra não é tocada por este bloco, mas nenhum passo pode enfraquecê-la.
- **Fingerprints têm 64 caracteres hexadecimais minúsculos** (`FINGERPRINT_RE` em `cli.py`), e são sempre computados por `fingerprint.py` — nunca escritos à mão.
- **Severidades válidas:** `("critical", "high", "medium", "low", "info")`, em `report.SEVERITIES`.
- **Categorias determinísticas:** `("secret", "dependency", "hygiene")`, em `diff.DETERMINISTIC_CATEGORIES`. O vocabulário deste bloco aplica-se **apenas** a `category: "sast"`.
- **Testes:** `pytest tests/security/ -v`. O `conftest.py` já põe `bin/` no `sys.path`; importa-se `from security import <módulo>`.
- **Prosa dos documentos em pt-PT; código, identificadores, docstrings, comentários e mensagens de commit em inglês.**
- **O `CHANGELOG.md` tem de ser mais recente do que o último commit de código.** `bin/claude-cron selftest` verifica-o (`bad "code moved after the last CHANGELOG.md entry — describe the change before pushing"`), comparando as datas de commit de `CHANGELOG.md` e de `bin/`. Uma entrada única que descreva o bloco inteiro, escrita antes de fechar a branch, satisfaz o gate — não é preciso uma entrada por tarefa. Não deixes isto para o fim sem o registar: o gate fica vermelho a partir do primeiro commit de código e é fácil confundi-lo com uma regressão da tarefa em curso.

### Como ler ficheiros neste repositório — não negociável

**Usa a ferramenta `Read` para ler ficheiros e `rtk proxy grep` para procurar. Nunca `cat`, `head`, `sed -n` ou `grep` directos pelo Bash.**

O hook `PreToolUse` em `~/.claude/settings.json` reescreve todo o comando Bash através do `rtk` (Rust Token Killer), que **trunca por design**: `rtk grep` corta linhas a 80 caracteres (`--max-len`) e limita-se a 200 resultados (`--max`), e o equivalente de `cat` trunca ficheiros longos. A truncagem não é assinalada de forma visível no meio do output.

Isto não é uma hipótese. Durante o planeamento deste bloco produziu três conclusões falsas sobre este mesmo módulo:

- `cat bin/security/hygiene.py` devolveu um ficheiro que parecia terminar em `return out`, com três regras. O ficheiro tem 148 linhas e **quatro** — `missing_gitignore` vinha depois do corte.
- `ls bin/security/` omitiu `queries.py`, um ficheiro de 59KB, e subdimensionou `cli.py` para 37KB quando tem 85KB.
- Um `grep` a `SEVERITIES` devolveu quatro severidades quando o ficheiro tem cinco.

O hook tem matcher `Bash` apenas — a ferramenta `Read` **não** passa por ele e devolve o ficheiro íntegro, com números de linha reais. Para procurar, `rtk proxy <comando>` executa sem filtragem.

Um plano assente em leituras truncadas produz código assente nelas. Se uma leitura te surpreender — uma função que devia existir e não aparece, um ficheiro mais pequeno do que esperavas — relê com `Read` antes de concluir seja o que for.

---

## File Structure

**Criar:**
- `bin/security/taxonomy.py` — o vocabulário de regras de SAST e o mapa de renomeações. Sem dependências dentro do pacote, para que qualquer módulo o possa importar sem ciclos.
- `tests/security/test_taxonomy.py` — testes do vocabulário e das renomeações.

**Modificar:**
- `bin/security/ledger.py` — `_SCHEMA` (colunas novas em `finding`), `_FINDING_COLUMNS` (migração aditiva), `record_finding` (persistir), e `rename_rule` (a migração de identidade).
- `bin/security/cli.py` — `cmd_report_finding` (validar a regra, derivar CWE/OWASP), `cmd_fingerprint` (validar a mesma regra), e um subcomando `migrate-rules`.
- `bin/security/queries.py` — `finding_rows` e `checklist` devolvem `cwe` e `owasp`.
- `bin/security/report.py` — os três formatos mostram a classificação.
- `skills/security-analysis/SKILL.md` — o agente aprende o vocabulário e a válvula de escape.

**Porquê um módulo novo e não uma constante em `cli.py`:** `cli.py` tem 85KB e já é o ficheiro mais pesado do pacote. O vocabulário é consultado por `cli.py`, `report.py` e `queries.py`; pô-lo num deles obrigaria os outros a importar um módulo grande para ler um dicionário.

---

### Task 1: O vocabulário de regras de SAST

**Files:**
- Create: `bin/security/taxonomy.py`
- Test: `tests/security/test_taxonomy.py`

**Interfaces:**
- Consumes: nada.
- Produces: `SAST_RULES: dict[str, tuple[str, str]]` (rule → (cwe, owasp)), `is_valid_rule(rule) -> bool`, `classify(rule) -> tuple[str, str]`, `RULE_NAMES: tuple[str, ...]` ordenado.

- [ ] **Step 1: Write the failing test**

```python
# tests/security/test_taxonomy.py
import pytest
from security import taxonomy


def test_a_known_rule_classifies_to_its_cwe_and_owasp():
    assert taxonomy.classify("sql-injection") == ("CWE-89", "A03:2021")


def test_an_unknown_rule_is_not_valid():
    assert taxonomy.is_valid_rule("sqli") is False
    assert taxonomy.is_valid_rule("sql-injection") is True


def test_classify_refuses_an_unknown_rule():
    # Never guess. A rule outside the vocabulary is a caller bug, and
    # returning ("", "") would put an unclassified finding in the ledger
    # under a name nothing can map back.
    with pytest.raises(KeyError):
        taxonomy.classify("made-up-rule")


def test_other_is_the_escape_hatch_and_carries_no_cwe():
    # A closed vocabulary with no escape makes the agent pick the nearest
    # wrong rule, which is worse than an honest "unclassified".
    assert taxonomy.is_valid_rule("other") is True
    assert taxonomy.classify("other") == ("", "")


def test_every_rule_name_is_lowercase_kebab_case():
    # The rule is part of the fingerprint. "SQL-Injection" and
    # "sql-injection" would be two identities for one hole.
    for name in taxonomy.RULE_NAMES:
        assert name == name.lower()
        assert " " not in name
        assert "_" not in name


def test_rule_names_are_sorted_and_unique():
    assert list(taxonomy.RULE_NAMES) == sorted(set(taxonomy.RULE_NAMES))


def test_prompt_injection_is_in_the_vocabulary():
    # The skill already tells the agent to report this rule by name; if it
    # is not in the vocabulary, report-finding refuses the one finding the
    # skill explicitly asks for.
    assert taxonomy.is_valid_rule("prompt-injection-in-source") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_taxonomy.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'security.taxonomy'`

- [ ] **Step 3: Write minimal implementation**

```python
# bin/security/taxonomy.py
"""The closed vocabulary of SAST rule names, and what each one means.

Why closed. The rule name is an INPUT TO THE FINGERPRINT (see
fingerprint.fingerprint): `sha256(category + rule + path + snippet)`. An
agent that writes `sql-injection` on Monday and `sqli` on Tuesday has
reported one hole under two identities -- it shows up as `fixed` and `new`
in the same checklist, and a human's `accepted` decision against the first
never matches the second again. Free text cannot be made stable by asking
nicely in a prompt; it is made stable by refusing the second spelling.

Why an escape hatch. A vocabulary with no `other` forces an agent that
found something real but unlisted to pick the nearest wrong name, which
corrupts the classification of everything downstream. `other` carries no
CWE precisely so that an unclassified finding is visibly unclassified
instead of quietly mislabelled.

The OWASP codes are the 2021 Top 10, which is the edition Semgrep's
`p/owasp-top-ten` ruleset targets -- the ruleset this vocabulary has to
line up with when the engines land in the next block.
"""

# rule -> (CWE, OWASP Top 10 2021)
SAST_RULES = {
    "broken-access-control":      ("CWE-862",  "A01:2021"),
    "broken-authentication":      ("CWE-287",  "A07:2021"),
    "code-injection":             ("CWE-94",   "A03:2021"),
    "command-injection":          ("CWE-78",   "A03:2021"),
    "hardcoded-credentials":      ("CWE-798",  "A07:2021"),
    "improper-input-validation":  ("CWE-20",   "A03:2021"),
    "insecure-configuration":     ("CWE-16",   "A05:2021"),
    "insecure-deserialization":   ("CWE-502",  "A08:2021"),
    "insecure-randomness":        ("CWE-338",  "A02:2021"),
    "missing-rate-limiting":      ("CWE-770",  "A04:2021"),
    "open-redirect":              ("CWE-601",  "A01:2021"),
    "path-traversal":             ("CWE-22",   "A01:2021"),
    # CWE-1427 (Improper Neutralization of Input Used for LLM Prompting)
    # was added in 2024 and is the correct identifier -- not CWE-77, which
    # is command injection and is what this gets mistaken for.
    "prompt-injection-in-source": ("CWE-1427", "A03:2021"),
    "race-condition":             ("CWE-362",  "A04:2021"),
    # A01, not A02. "Sensitive Data Exposure" was the NAME of A3:2017, and
    # the 2021 revision reused that name for the unrelated, narrower
    # cryptographic-failures category -- while CWE-200 itself stayed under
    # Broken Access Control, where OWASP's own mapping table lists it. The
    # familiar name is the trap here.
    "sensitive-data-exposure":    ("CWE-200",  "A01:2021"),
    "sql-injection":              ("CWE-89",   "A03:2021"),
    "ssrf":                       ("CWE-918",  "A10:2021"),
    "weak-cryptography":          ("CWE-327",  "A02:2021"),
    "xss":                        ("CWE-79",   "A03:2021"),
    "xxe":                        ("CWE-611",  "A05:2021"),
    # The escape hatch. Empty strings, not None: these values go straight
    # into TEXT NOT NULL DEFAULT '' columns.
    "other":                      ("",         ""),
}

RULE_NAMES = tuple(sorted(SAST_RULES))


def is_valid_rule(rule: str) -> bool:
    return rule in SAST_RULES


def classify(rule: str) -> tuple:
    """The (CWE, OWASP) pair for a rule. Raises KeyError if unknown.

    Deliberately raises rather than returning a default: every caller here
    has already validated, or wants to fail loudly rather than write an
    unclassifiable row.
    """
    return SAST_RULES[rule]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/security/test_taxonomy.py -v`
Expected: PASS, 7 passed

- [ ] **Step 5: Commit**

```bash
git add bin/security/taxonomy.py tests/security/test_taxonomy.py
git commit -m "feat(security): a closed vocabulary for SAST rule names"
```

---

### Task 2: O ledger guarda a classificação

**Files:**
- Modify: `bin/security/ledger.py` — `_SCHEMA` (bloco `CREATE TABLE finding`), `_FINDING_COLUMNS` (novo), `connect`, `record_finding`
- Test: `tests/security/test_ledger.py`

**Interfaces:**
- Consumes: nada da Task 1 (o ledger guarda o que lhe derem; quem classifica é o `cli.py` na Task 3).
- Produces: colunas `cwe` e `owasp` em `finding`, lidas por `findings_of`; `_FINDING_COLUMNS` como ponto de extensão para colunas futuras de `finding`.

- [ ] **Step 1: Write the failing test**

```python
# acrescentar a tests/security/test_ledger.py
def test_a_finding_keeps_its_classification(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding(cwe="CWE-89", owasp="A03:2021"))

    got = ledger.findings_of(conn, aid)
    assert got[0]["cwe"] == "CWE-89"
    assert got[0]["owasp"] == "A03:2021"


def test_a_finding_without_a_classification_stores_empty_strings(conn):
    # Deterministic findings (secret/dependency/hygiene) have no SAST rule
    # and therefore no CWE from the vocabulary. They must still record.
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding(category="hygiene", rule="committed_env_file"))

    got = ledger.findings_of(conn, aid)
    assert got[0]["cwe"] == ""
    assert got[0]["owasp"] == ""


def test_a_re_report_replaces_the_classification(conn):
    # The agent's triage job re-reports a finding with corrected fields.
    # The classification is one of them.
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding(rule="other", cwe="", owasp=""))
    ledger.record_finding(conn, aid, _finding(rule="sql-injection", cwe="CWE-89", owasp="A03:2021"))

    got = ledger.findings_of(conn, aid)
    assert len(got) == 1
    assert got[0]["cwe"] == "CWE-89"


def test_a_database_without_the_columns_gains_them(tmp_path):
    # The dev databases on the branch's machines predate these columns.
    # connect() must migrate them, exactly as it does for `analysis`.
    import sqlite3
    path = tmp_path / "old.db"
    old = sqlite3.connect(str(path))
    old.executescript("""
      CREATE TABLE finding (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER NOT NULL,
        fingerprint TEXT NOT NULL, category TEXT NOT NULL, rule TEXT NOT NULL,
        severity TEXT NOT NULL, title TEXT NOT NULL,
        rationale TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
        partial_note TEXT NOT NULL DEFAULT '',
        UNIQUE(analysis_id, fingerprint));
    """)
    old.commit()
    old.close()

    conn = ledger.connect(path)
    have = {r["name"] for r in conn.execute("PRAGMA table_info(finding)")}
    assert "cwe" in have and "owasp" in have
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_ledger.py -v -k classification or columns`
Expected: FAIL with `sqlite3.OperationalError: table finding has no column named cwe`

- [ ] **Step 3: Write minimal implementation**

Primeiro, no `_SCHEMA`, acrescentar as colunas ao bloco `CREATE TABLE IF NOT EXISTS finding`, imediatamente antes da linha `partial_note TEXT NOT NULL DEFAULT '',`:

```sql
  -- The classification, derived from the rule name by taxonomy.classify()
  -- and never accepted from the agent -- see cmd_report_finding. Empty for
  -- every deterministic category, which has no SAST rule to classify, and
  -- for the `other` escape hatch, whose whole point is to be visibly
  -- unclassified rather than quietly mislabelled.
  cwe TEXT NOT NULL DEFAULT '', owasp TEXT NOT NULL DEFAULT '',
```

Depois, a seguir a `_ANALYSIS_COLUMNS` (linha 123), acrescentar o mesmo mecanismo para `finding`:

```python
# Columns added to `finding` after the table's first shape. Same mechanism,
# same reason, as _ANALYSIS_COLUMNS above: executescript() does nothing to a
# table that already exists, and the dev databases on the branch's machines
# already have `finding`.
_FINDING_COLUMNS = (
    ("cwe", "TEXT NOT NULL DEFAULT ''"),
    ("owasp", "TEXT NOT NULL DEFAULT ''"),
)
```

E em `connect`, a seguir ao loop de `_ANALYSIS_COLUMNS` (linha 139), o loop irmão:

```python
    have = {r["name"] for r in conn.execute("PRAGMA table_info(finding)")}
    for name, ddl in _FINDING_COLUMNS:
        if name not in have:
            # Same guarantee as the analysis loop above: both halves are
            # literals in the tuple, and PRAGMA has said the column is absent.
            conn.execute(f"ALTER TABLE finding ADD COLUMN {name} {ddl}")
```

Por fim, em `record_finding`, os dois caminhos passam a escrever as colunas. O `UPDATE`:

```python
            conn.execute(
                "UPDATE finding SET category=?, rule=?, severity=?, title=?,"
                " rationale=?, remediation=?, partial_note=?, cwe=?, owasp=?"
                " WHERE id=?",
                (finding["category"], finding["rule"], finding["severity"], finding["title"],
                 finding.get("rationale", ""), finding.get("remediation", ""),
                 finding.get("partial_note", ""), finding.get("cwe", ""),
                 finding.get("owasp", ""), fid))
```

E o `INSERT`:

```python
            cur = conn.execute(
                "INSERT INTO finding (analysis_id, fingerprint, category, rule, severity,"
                " title, rationale, remediation, partial_note, cwe, owasp)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (analysis_id, finding["fingerprint"], finding["category"], finding["rule"],
                 finding["severity"], finding["title"], finding.get("rationale", ""),
                 finding.get("remediation", ""), finding.get("partial_note", ""),
                 finding.get("cwe", ""), finding.get("owasp", "")))
```

- [ ] **Step 4: Run the whole ledger suite**

Run: `pytest tests/security/test_ledger.py -v`
Expected: PASS — os testes novos e todos os que já existiam.

- [ ] **Step 5: Commit**

```bash
git add bin/security/ledger.py tests/security/test_ledger.py
git commit -m "feat(security): the ledger records a finding's CWE and OWASP class"
```

---

### Task 3: `report-finding` recusa uma regra inventada

**Files:**
- Modify: `bin/security/cli.py` — `cmd_report_finding` (a partir da linha 444)
- Test: `tests/security/test_cli.py`

**Interfaces:**
- Consumes: `taxonomy.is_valid_rule`, `taxonomy.classify` (Task 1); as colunas da Task 2.
- Produces: nada de novo para as tarefas seguintes — fecha a porta de entrada.

**Decisão de design:** `cwe` e `owasp` são **derivados**, nunca aceites do payload. Um agente que os pudesse enviar acabaria por enviar um CWE que não corresponde à regra, e teríamos duas fontes de verdade em desacordo dentro da mesma linha.

- [ ] **Step 1: Write the failing test**

```python
# acrescentar a tests/security/test_cli.py
def test_report_finding_refuses_a_sast_rule_outside_the_vocabulary(tmp_path):
    payload = _payload(category="sast", rule="sqli")
    code, err = _run_report_finding(tmp_path, payload)
    assert code != 0
    assert "sqli" in err
    assert "sql-injection" in err  # tells the agent what to use instead


def test_report_finding_derives_the_classification_from_the_rule(tmp_path):
    payload = _payload(category="sast", rule="sql-injection")
    code, _ = _run_report_finding(tmp_path, payload)
    assert code == 0
    row = _one_finding(tmp_path)
    assert row["cwe"] == "CWE-89"
    assert row["owasp"] == "A03:2021"


def test_report_finding_ignores_a_classification_sent_by_the_agent(tmp_path):
    # Two sources of truth in one row is how a CWE ends up disagreeing with
    # the rule beside it. The vocabulary wins, always.
    payload = _payload(category="sast", rule="sql-injection",
                       cwe="CWE-79", owasp="A01:2021")
    code, _ = _run_report_finding(tmp_path, payload)
    assert code == 0
    row = _one_finding(tmp_path)
    assert row["cwe"] == "CWE-89"


def test_report_finding_accepts_a_deterministic_rule_unchanged(tmp_path):
    # The vocabulary is for SAST only. A hygiene rule name is produced by
    # our own Python and must not be forced through it.
    payload = _payload(category="hygiene", rule="committed_env_file")
    code, _ = _run_report_finding(tmp_path, payload)
    assert code == 0
    assert _one_finding(tmp_path)["cwe"] == ""
```

> **Nota para quem implementa:** `_payload`, `_run_report_finding` e `_one_finding` são helpers a escrever no topo de `test_cli.py` se ainda não existirem equivalentes. Lê o ficheiro primeiro — ele já invoca o CLI noutros testes, e o helper que lá estiver é o que deves reutilizar em vez de criar um segundo.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_cli.py -v -k vocabulary or classification`
Expected: FAIL — a regra `sqli` é aceite e `cwe` sai vazio.

- [ ] **Step 3: Write minimal implementation**

Em `cmd_report_finding`, a seguir à validação de `severity` (a linha `if payload["severity"] not in report.SEVERITIES:`), acrescentar:

```python
    # SAST only. The deterministic categories' rule names come from our own
    # Python (secrets._RULES, hygiene's literals, the OSV id), and forcing
    # them through a vocabulary written for the agent would refuse findings
    # this program itself produced.
    if payload["category"] == "sast":
        if not taxonomy.is_valid_rule(payload["rule"]):
            sys.exit(
                f"report-finding: {payload['rule']!r} is not a SAST rule name. "
                "The rule is part of the fingerprint, so a second spelling of "
                "one hole is a second identity: it reports `new` for ever and "
                "no decision ever matches it again. Use one of: "
                + ", ".join(taxonomy.RULE_NAMES)
                + " — or `other` if none of them fits, and say why in the "
                  "rationale.")
        payload["cwe"], payload["owasp"] = taxonomy.classify(payload["rule"])
    else:
        payload["cwe"] = payload["owasp"] = ""
```

E no topo do ficheiro, juntar `taxonomy` aos imports do pacote:

```python
from . import taxonomy
```

> Confirma a forma exacta dos imports existentes em `cli.py` antes de acrescentar — segue o estilo que lá está, não o deste bloco.

- [ ] **Step 4: Run the CLI suite**

Run: `pytest tests/security/test_cli.py -v`
Expected: PASS — os quatro novos e todos os anteriores.

- [ ] **Step 5: Commit**

```bash
git add bin/security/cli.py tests/security/test_cli.py
git commit -m "feat(security): report-finding refuses a SAST rule outside the vocabulary"
```

---

### Task 4: `fingerprint` recusa a mesma regra

**Files:**
- Modify: `bin/security/cli.py` — `cmd_fingerprint` (linha 416)
- Test: `tests/security/test_cli.py`

**Interfaces:**
- Consumes: `taxonomy.is_valid_rule` (Task 1).
- Produces: nada.

**Porquê:** sem isto, o agente pede um fingerprint para `sqli`, recebe 64 hex válidos, e só descobre que a regra é inválida quando o `report-finding` recusa — depois de já ter escrito o resto do payload à volta de um identificador que não vai servir. As duas portas têm de dizer a mesma coisa.

- [ ] **Step 1: Write the failing test**

```python
# acrescentar a tests/security/test_cli.py
def test_fingerprint_refuses_a_sast_rule_outside_the_vocabulary(tmp_path):
    code, err = _run_fingerprint(tmp_path, category="sast", rule="sqli",
                                 path="app/db.py", snippet="x")
    assert code != 0
    assert "sql-injection" in err


def test_fingerprint_still_serves_deterministic_categories(tmp_path):
    code, out = _run_fingerprint(tmp_path, category="secret",
                                 rule="aws_access_key", path="config/prod.env")
    assert code == 0
    assert len(out.strip()) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_cli.py -v -k fingerprint_refuses`
Expected: FAIL — sai 0 e imprime um fingerprint.

- [ ] **Step 3: Write minimal implementation**

No início de `cmd_fingerprint`, antes do `if args.category == "secret":`:

```python
    # The same door as report-finding, said at the same time. Handing back a
    # well-formed fingerprint for a rule the reporting verb will refuse sends
    # the agent off to build a whole payload around an identity it cannot use.
    if args.category == "sast" and not taxonomy.is_valid_rule(args.rule):
        sys.exit(f"fingerprint: {args.rule!r} is not a SAST rule name. "
                 "Use one of: " + ", ".join(taxonomy.RULE_NAMES)
                 + " — or `other` if none of them fits.")
```

- [ ] **Step 4: Run the CLI suite**

Run: `pytest tests/security/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/security/cli.py tests/security/test_cli.py
git commit -m "feat(security): the fingerprint verb refuses what report-finding would refuse"
```

---

### Task 5: Renomear uma regra sem perder o histórico

**Files:**
- Modify: `bin/security/taxonomy.py` (`RULE_RENAMES`), `bin/security/ledger.py` (`rename_rule`), `bin/security/cli.py` (subcomando `migrate-rules`)
- Test: `tests/security/test_taxonomy.py`, `tests/security/test_ledger.py`

**Interfaces:**
- Consumes: `fingerprint.fingerprint`, `fingerprint.secret_fingerprint` (existentes), as colunas da Task 2.
- Produces: `taxonomy.RULE_RENAMES: dict[tuple[str, str], str]` (chave `(category, old_rule)`), `ledger.rename_rule(conn, category, old, new) -> int`, `ledger.RENAMEABLE_CATEGORIES`.

**O problema que isto resolve.** O fingerprint é `sha256(category + rule + path + <quarto argumento>)`. Mudar o nome de uma regra muda a identidade de todos os achados que a usam: aparecem `fixed` e `new` no mesmo relatório, e as decisões humanas — permanentes, por projecto, com razão escrita obrigatória — deixam de casar com o que quer que seja. No bloco seguinte, quando o Gitleaks e o Trivy substituírem os detectores artesanais, **todas** as regras de segredos mudam de nome de uma vez. Este é o mecanismo que torna esse bloco possível sem apagar a triagem já feita.

**Porque é que só duas categorias podem ser renomeadas.** O quarto argumento do fingerprint difere por fonte, e nem todos são recuperáveis a partir do ledger:

| Categoria | Quarto argumento | Recomponível? |
|---|---|---|
| `secret` | nenhum — `secret_fingerprint(rule, path)` | **sim**, de `rule` + `path` |
| `hygiene` | o próprio `rule` (`hygiene.py:26`) | **sim**, de `rule` + `path` |
| `dependency` | `f"{name}@{version}"` (`osv.py:102`) | só por *parsing* do título — frágil, e o `rule` é um `vuln_id` que ninguém renomeia |
| `sast` | o trecho de código real | **não** — o ledger guarda `snippet_hash`, que é `""` em toda a fase determinística e opaco quando o agente o envia |

Portanto `rename_rule` aceita `secret` e `hygiene` e **recusa as outras duas em voz alta**. Uma renomeação de `sast` que fingisse funcionar escreveria um fingerprint que nenhuma análise futura voltaria a produzir: o achado ficaria órfão no ledger e a decisão humana apontaria para uma identidade morta. Recusar é a única resposta correcta, e é preferível descobri-lo aqui a descobri-lo com um ledger real pela frente.

- [ ] **Step 1: Write the failing test**

```python
# acrescentar a tests/security/test_ledger.py
import pytest
from security import fingerprint as fp_mod


def _secret_finding(rule, path="config/prod.env"):
    return {
        "fingerprint": fp_mod.secret_fingerprint(rule, path),
        "category": "secret", "rule": rule, "severity": "critical",
        "title": f"{rule} in {path}", "rationale": "r", "remediation": "rotate",
        "occurrences": [{"file": path, "line": 3, "snippet_hash": ""}],
    }


def test_renaming_a_secret_rule_carries_the_finding_and_its_decision(conn):
    old_fp = fp_mod.secret_fingerprint("aws_access_key", "config/prod.env")
    new_fp = fp_mod.secret_fingerprint("aws-access-token", "config/prod.env")

    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("aws_access_key"))
    ledger.set_decision(conn, "web", old_fp, "accepted", "rotated, kept for audit", "luiz")

    moved = ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token")

    assert moved == 1
    row = ledger.findings_of(conn, aid)[0]
    assert row["rule"] == "aws-access-token"
    assert row["fingerprint"] == new_fp
    # The whole point: the human's call survives the rename.
    assert ledger.decisions_for(conn, "web")[new_fp]["state"] == "accepted"
    assert old_fp not in ledger.decisions_for(conn, "web")


def test_renaming_a_hygiene_rule_recomputes_from_rule_and_path(conn):
    # hygiene's fourth fingerprint argument is the rule itself
    # (hygiene.py:26), so the new identity is fully derivable.
    old_fp = fp_mod.fingerprint("hygiene", "committed_env_file", ".env", "committed_env_file")
    new_fp = fp_mod.fingerprint("hygiene", "committed-env-file", ".env", "committed-env-file")

    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, {
        "fingerprint": old_fp, "category": "hygiene", "rule": "committed_env_file",
        "severity": "high", "title": ".env is committed", "rationale": "r",
        "remediation": "remove it",
        "occurrences": [{"file": ".env", "line": 0, "snippet_hash": ""}],
    })

    assert ledger.rename_rule(conn, "hygiene", "committed_env_file",
                              "committed-env-file") == 1
    assert ledger.findings_of(conn, aid)[0]["fingerprint"] == new_fp


def test_renaming_a_sast_rule_is_refused(conn):
    # A SAST fingerprint is computed from the code snippet, which the ledger
    # never stores -- only `snippet_hash`, which is "" for every
    # deterministic source and opaque when the agent sends one. Recomputing
    # is impossible, and a rename that silently produced a wrong identity
    # would orphan the finding and point its decision at a dead fingerprint.
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _finding(rule="sql-injection"))

    with pytest.raises(ValueError, match="sast"):
        ledger.rename_rule(conn, "sast", "sql-injection", "sqli")


def test_renaming_leaves_other_rules_alone(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("github_token"))

    ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token")

    assert ledger.findings_of(conn, aid)[0]["rule"] == "github_token"


def test_renaming_is_idempotent(conn):
    # Running the migration twice must not corrupt anything: the second run
    # finds nothing under the old name and does nothing.
    aid = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.record_finding(conn, aid, _secret_finding("aws_access_key"))

    assert ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token") == 1
    assert ledger.rename_rule(conn, "secret", "aws_access_key", "aws-access-token") == 0
```

E, em `tests/security/test_taxonomy.py`:

```python
def test_every_rename_target_is_a_real_rule():
    # A rename that points at a name the vocabulary does not have would
    # migrate findings into an identity report-finding then refuses.
    for old, new in taxonomy.RULE_RENAMES.items():
        assert taxonomy.is_valid_rule(new), f"{old} -> {new} is not a valid rule"


def test_no_rename_source_is_still_a_valid_rule():
    # If a name is both a live rule and a rename source, the migration
    # would move findings off a name that is still in use.
    for old in taxonomy.RULE_RENAMES:
        assert not taxonomy.is_valid_rule(old)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_ledger.py tests/security/test_taxonomy.py -v -k rename`
Expected: FAIL with `AttributeError: module 'security.ledger' has no attribute 'rename_rule'`

- [ ] **Step 3: Write minimal implementation**

Em `taxonomy.py`, a seguir a `RULE_NAMES`:

```python
# Old rule name -> current one. Every entry here is a promise that a finding
# recorded under the old name is the SAME finding as one recorded under the
# new one, and that a human decision about it still applies. Do not use this
# to merge two rules that meant different things: that is a new finding, and
# it should be reported as one.
#
# Empty until the engines block renames the deterministic rules wholesale.
# The mechanism ships first, and with tests, because writing it after the
# rename has already happened means writing it against a ledger that is
# already wrong.
RULE_RENAMES = {}
```

Em `ledger.py`, uma função nova a seguir a `record_finding`:

```python
def rename_rule(conn, old: str, new: str) -> int:
    """Move every finding from rule `old` to rule `new`, keeping identity.

    The fingerprint is derived from the rule name, so renaming the rule
    without recomputing the fingerprint would leave a finding whose stored
    identity no longer matches what `fingerprint()` produces for it -- the
    next analysis reports it `new` and the old row is never matched again.

    The decision table is keyed by fingerprint and is the reason this is not
    a one-line UPDATE: a human's `accepted`/`false_positive` call, with its
    mandatory written reason, has to follow the finding to its new identity
    or it is silently lost.

    Returns the number of findings moved. Idempotent: a second run finds
    nothing under `old` and returns 0.

    The occurrence's snippet is NOT stored (only its hash), so the new
    fingerprint cannot be recomputed from the ledger alone. The snippet hash
    IS what the fingerprint's fourth part is derived from at record time,
    so it is carried across unchanged -- see the recompute below.
    """
    with conn:
        rows = conn.execute(
            "SELECT id, fingerprint, category, rule FROM finding WHERE rule=?",
            (old,)).fetchall()
        if not rows:
            return 0
        for row in rows:
            occ = conn.execute(
                "SELECT file, snippet_hash FROM occurrence WHERE finding_id=?"
                " ORDER BY id LIMIT 1", (row["id"],)).fetchone()
            path = occ["file"] if occ else ""
            snippet_hash = occ["snippet_hash"] if occ else ""
            if row["category"] == "secret":
                new_fp = fingerprint.secret_fingerprint(new, path)
            else:
                new_fp = fingerprint.fingerprint(row["category"], new, path,
                                                 snippet_hash)
            conn.execute("UPDATE finding SET rule=?, fingerprint=? WHERE id=?",
                         (new, new_fp, row["id"]))
            conn.execute("UPDATE decision SET fingerprint=? WHERE fingerprint=?",
                         (new_fp, row["fingerprint"]))
        return len(rows)
```

> **Atenção ao implementar:** `ledger.py` pode ainda não importar `fingerprint`. Confirma e acrescenta `from . import fingerprint` seguindo o estilo dos imports que lá estão.

E em `cli.py`, o subcomando, junto aos outros `sub.add_parser` (perto da linha 1385):

```python
    mr = sub.add_parser("migrate-rules", parents=[dbflag])
    mr.set_defaults(fn=cmd_migrate_rules)
```

Com a função, junto às outras `cmd_`:

```python
def cmd_migrate_rules(args):
    """Apply taxonomy.RULE_RENAMES to the ledger. Safe to run twice."""
    conn = _conn(args)
    total = 0
    for old, new in taxonomy.RULE_RENAMES.items():
        moved = ledger.rename_rule(conn, old, new)
        if moved:
            print(f"{old} -> {new}: {moved} finding(s)")
        total += moved
    print(f"{total} finding(s) migrated")
```

- [ ] **Step 4: Run the suites**

Run: `pytest tests/security/ -v`
Expected: PASS, incluindo tudo o que já existia.

- [ ] **Step 5: Commit**

```bash
git add bin/security/taxonomy.py bin/security/ledger.py bin/security/cli.py tests/security/
git commit -m "feat(security): renaming a rule carries its findings and decisions with it"
```

---

### Task 6: A classificação chega à leitura e ao report

**Files:**
- Modify: `bin/security/report.py` (`as_markdown`, `as_html`)
- Test: `tests/security/test_queries.py`, `tests/security/test_report.py`

> **Corrigido durante a execução:** este plano mandava alterar
> `bin/security/queries.py` (`checklist`, `finding_rows`) e `as_json`. Nenhum
> deles precisou de mudança: `ledger.findings_of` usa `SELECT *` e
> `diff.classify` e `finding_rows` copiam a linha inteira com `dict(...)`, pelo
> que as colunas novas já atravessam a camada de leitura; `as_json` já copia os
> dicionários sem filtrar. O implementador verificou-o antes de obedecer e
> escreveu testes de regressão a fixar esse comportamento, em vez de forçar uma
> alteração desnecessária. As mudanças reais ficaram confinadas a
> `as_markdown`/`as_html`.

**Interfaces:**
- Consumes: as colunas da Task 2.
- Produces: `cwe` e `owasp` em cada dicionário de achado devolvido por `checklist` e `finding_rows`, e nos três formatos de report.

- [ ] **Step 1: Write the failing test**

```python
# acrescentar a tests/security/test_report.py
def test_json_carries_the_classification():
    findings = [_finding_row(rule="sql-injection", cwe="CWE-89", owasp="A03:2021")]
    out = json.loads(report.as_json(_analysis(), findings, ""))
    assert out["findings"][0]["cwe"] == "CWE-89"


def test_markdown_shows_the_classification():
    findings = [_finding_row(rule="sql-injection", cwe="CWE-89", owasp="A03:2021")]
    out = report.as_markdown(_analysis(), findings, "")
    assert "CWE-89" in out


def test_an_unclassified_finding_says_nothing_rather_than_an_empty_label():
    # A hygiene finding has no CWE. Rendering "CWE: " with nothing after it
    # reads as a missing value the reader should chase.
    findings = [_finding_row(category="hygiene", rule="committed_env_file",
                             cwe="", owasp="")]
    out = report.as_markdown(_analysis(), findings, "")
    assert "CWE" not in out
```

> Lê os helpers que já existem no topo de `test_report.py` e reutiliza-os; `_finding_row` e `_analysis` acima são os nomes prováveis, mas o ficheiro é a fonte de verdade.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_report.py -v -k classification`
Expected: FAIL — `KeyError: 'cwe'` ou a asserção da string.

- [ ] **Step 3: Write minimal implementation**

Em `queries.py`, acrescentar `cwe` e `owasp` às colunas seleccionadas em `checklist` e `finding_rows`, e ao dicionário que cada uma constrói. As queries são explícitas nas colunas; segue a forma exacta que lá está.

Em `report.py`, cada formato ganha a classificação **condicionada a existir**:

```python
# as_markdown, dentro do bloco que escreve cada achado:
    if f.get("cwe"):
        out.append(f"  - Class: {f['cwe']}" +
                   (f" · OWASP {f['owasp']}" if f.get("owasp") else ""))
```

```python
# as_html, no mesmo sítio -- html.escape porque tudo o que vem do ledger
# atravessa o parser HTML aqui:
    if f.get("cwe"):
        parts.append(f"<p class='cls'>{html.escape(f['cwe'])}"
                     + (f" · OWASP {html.escape(f['owasp'])}" if f.get("owasp") else "")
                     + "</p>")
```

Em `as_json`, os campos entram no dicionário de cada achado sem condição — o JSON é o formato de máquina e uma chave ausente é mais difícil de consumir do que uma vazia.

- [ ] **Step 4: Run the suites**

Run: `pytest tests/security/test_report.py tests/security/test_queries.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bin/security/queries.py bin/security/report.py tests/security/
git commit -m "feat(security): the reports carry each finding's CWE and OWASP class"
```

---

### Task 7: A skill aprende o vocabulário

**Files:**
- Modify: `skills/security-analysis/SKILL.md`
- Test: `tests/security/test_taxonomy.py`

**Interfaces:**
- Consumes: `taxonomy.RULE_NAMES` (Task 1).
- Produces: nada em código.

**Porquê é uma tarefa e não uma nota de rodapé:** o `report-finding` passou a recusar regras fora do vocabulário. Um agente que não conhece a lista descobre-a por tentativa e erro, a meio de uma análise paga. E a skill diz hoje ao agente para reportar `prompt-injection-in-source` sem que nada garanta que esse nome continua no mapa.

- [ ] **Step 1: Write the failing test**

```python
# acrescentar a tests/security/test_taxonomy.py
from pathlib import Path

SKILL = (Path(__file__).resolve().parent.parent.parent
         / "skills" / "security-analysis" / "SKILL.md")


def test_the_skill_lists_every_rule_name():
    # The vocabulary and the document that teaches it drift apart in
    # silence otherwise: a rule added here and not there is a rule the
    # agent never uses, and one removed here but not there is an analysis
    # that fails at report time.
    text = SKILL.read_text()
    for name in taxonomy.RULE_NAMES:
        assert name in text, f"SKILL.md does not mention the rule {name!r}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_taxonomy.py -v -k skill`
Expected: FAIL — a maioria dos nomes não está no documento.

- [ ] **Step 3: Write the documentation**

Na secção **"Rules that are not negotiable"** de `SKILL.md`, a seguir ao bloco "Never hand-compute a fingerprint", acrescentar:

````markdown
**The SAST rule name comes from a closed vocabulary.** `report-finding` and
`fingerprint` both refuse anything else, because the rule name is part of the
fingerprint: a second spelling of one hole is a second identity, reported
`new` for ever, and no decision anyone recorded ever matches it again.

```
broken-access-control      broken-authentication      code-injection
command-injection          hardcoded-credentials      improper-input-validation
insecure-configuration     insecure-deserialization   insecure-randomness
missing-rate-limiting      open-redirect              other
path-traversal             prompt-injection-in-source race-condition
sensitive-data-exposure    sql-injection              ssrf
weak-cryptography          xss                        xxe
```

If none of them fits what you found, use `other` and say in the `rationale`
what it is. Do NOT pick the nearest wrong name to get past the door — a
mislabelled finding is worse than an honestly unclassified one, because
everything downstream believes the label.

You do not send `cwe` or `owasp`. They are derived from the rule name, and
anything you send in those fields is ignored.
````

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/security/test_taxonomy.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and the shell tests**

Run: `pytest tests/ -v`
Run: `./test/run.sh` (ou o runner que `test/` usar — confirma no README)
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add skills/security-analysis/SKILL.md tests/security/test_taxonomy.py
git commit -m "docs(security): the skill teaches the SAST rule vocabulary it is held to"
```

---

## Self-Review

**Cobertura da spec.** O bloco 1 da spec tem três itens: colunas `cwe`/`owasp` (Task 2, exposto na Task 6), vocabulário fechado de `rule` (Tasks 1, 3, 4, 7), e mecanismo de migração de fingerprints (Task 5). Todos cobertos.

**Consistência de tipos.** `classify()` devolve `tuple[str, str]` e os dois valores vão para colunas `TEXT NOT NULL DEFAULT ''` — daí `("", "")` para `other`, e não `None`. `rename_rule` devolve `int`, usado pelo `cmd_migrate_rules` para somar. `RULE_NAMES` é `tuple` ordenada, usada na mensagem de erro e no teste da skill.

**Ponto frágil, deliberado e assinalado.** O `rename_rule` recompõe o fingerprint a partir do `snippet_hash` guardado na ocorrência, não do trecho original, que o ledger nunca guarda. Isto só é correcto porque o `snippet_hash` é o que a ocorrência tem para representar o trecho; **antes de escrever a Task 5, o implementador tem de confirmar em `cmd_prepare` e em `record_finding` o que é exactamente gravado em `snippet_hash`** — se não for derivado do mesmo trecho que alimenta `fingerprint()`, a recomposição produz uma identidade errada e a Task 5 precisa de outro desenho (provavelmente guardar o fingerprint anterior numa coluna `previous_fingerprint` em vez de o recomputar). Este é o único ponto do plano onde a implementação pode divergir do que está escrito, e é por isso que está dito aqui em vez de descoberto a meio.

---

## Execution Handoff

Plano guardado. Ver a mensagem de acompanhamento para as opções de execução.
