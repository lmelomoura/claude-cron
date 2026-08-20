# Security Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** dar ao claude-cron uma área de segurança autónoma — escolher um projecto e uma branch, correr uma análise, obter um report descarregável, e na corrida seguinte ver o que ficou resolvido, o que não ficou, o que ficou a meio e o que é novo.

**Architecture:** uma camada determinística em Python (segredos, dependências, SBOM, higiene) escreve um ledger SQLite em segundos e sem tokens; depois um agente Claude faz o SAST, a triagem e a reverificação, reportando através do CLI e nunca escrevendo no ledger. A análise corre como um run normal de `run_job`, sobre um job **derivado em memória** a partir da configuração de segurança do projecto — `jobs_json` emite-o, e nem o tick nem o servidor nem `write_jobs` o vêem.

**Tech Stack:** bash (engine), Python 3 stdlib **apenas** (sem pip), SQLite, jq, HTML/JS sem build step.

**Spec:** `docs/superpowers/specs/2026-08-20-security-analysis-design.md` — lê-a antes da Task 1.

## Global Constraints

- **macOS.** `launchd`, BSD `date`, BSD `sed`. Nada de GNU-isms.
- **Sem dependências novas.** Só `jq`, `python3` (stdlib) e `curl` já exigidos. **Nenhum `pip install`** — HTTP é `urllib.request`, o SBOM é JSON escrito à mão. Nenhum binário de scanning externo (semgrep, trivy, gitleaks): não existem nesta máquina e não vão passar a existir.
- **`CHANGELOG.md` na mesma alteração que o código**, sempre que a tarefa toca em `bin/`, `skills/` ou `test/`. `claude-cron selftest` falha se não for. Uma entrada diz o que mudou de comportamento e o que custava não o ter.
- **Uma regra que o código exige viaja com o código.** `config/` é git-ignorado; nada de que o motor dependa pode viver só lá.
- **Idioma:** prosa em pt-PT nos documentos que o utilizador revê; **código, identificadores, docstrings, comentários e mensagens de commit em inglês**.
- **O valor de um segredo nunca é persistido nem impresso** — nem no ledger, nem em report nenhum, nem no log do run, nem mascarado.
- Ficheiros focados. `bin/security/` é um módulo por responsabilidade; nenhum deles deve crescer para além de ~250 linhas.
- Testes Python em `tests/security/`, corridos por `pytest tests/`. Asserções de engine em `claude-cron selftest`.

## File Structure

| Ficheiro | Responsabilidade |
|---|---|
| `bin/security/__init__.py` | marca o package; vazio |
| `bin/security/fingerprint.py` | identidade estável de um achado, com a excepção dos segredos |
| `bin/security/ledger.py` | schema SQLite e todos os acessos a `data/security.db` |
| `bin/security/diff.py` | os seis estados da checklist, derivados |
| `bin/security/secrets.py` | detecção de segredos na árvore e no histórico |
| `bin/security/deps.py` | inventário a partir de lockfiles, e SBOM CycloneDX |
| `bin/security/osv.py` | cliente OSV.dev, com degradação declarada |
| `bin/security/hygiene.py` | higiene de repositório |
| `bin/security/report.py` | Markdown, JSON e HTML a partir do ledger |
| `bin/security/cli.py` | ponto de entrada que o bash invoca |
| `bin/claude-cron` | jobs derivados, prefixo reservado, subcomando `security` |
| `bin/worktree-lib.sh` | branch explícita via `CC_BASE_OVERRIDE` |
| `bin/claude-cron-server` | endpoints da área |
| `bin/dashboard.html` | view `security` e separador no editor de projecto |
| `skills/security-analysis/SKILL.md` | contrato do agente |
| `tests/security/` | pytest da camada Python |

---

## Task 1: Fingerprint

**Files:**
- Create: `bin/security/__init__.py`, `bin/security/fingerprint.py`
- Test: `tests/security/test_fingerprint.py`, `tests/security/conftest.py`

**Interfaces:**
- Consumes: nada.
- Produces: `fingerprint(category: str, rule: str, path: str, snippet: str) -> str` e `secret_fingerprint(secret_type: str, path: str, ordinal: int) -> str`, ambos devolvendo 64 hex chars.

- [ ] **Step 1: Write the failing test**

```python
# tests/security/conftest.py
"""Loads bin/security as a package. bin/ has no __init__ chain of its own."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "bin"))
```

```python
# tests/security/test_fingerprint.py
from security.fingerprint import fingerprint, secret_fingerprint


def test_reformatting_does_not_change_the_fingerprint():
    a = fingerprint("sast", "sql-injection", "app/db.py", "query = 'SELECT ' + name")
    b = fingerprint("sast", "sql-injection", "app/db.py", "query   =  'SELECT ' + name  ")
    assert a == b


def test_a_real_change_does_change_it():
    a = fingerprint("sast", "sql-injection", "app/db.py", "query = 'SELECT ' + name")
    b = fingerprint("sast", "sql-injection", "app/db.py", "query = 'SELECT ' + other")
    assert a != b


def test_the_path_is_part_of_the_identity():
    a = fingerprint("sast", "sql-injection", "app/db.py", "x = 1")
    b = fingerprint("sast", "sql-injection", "app/web.py", "x = 1")
    assert a != b


def test_a_secret_fingerprint_never_contains_the_value():
    """The value is not an argument at all — it cannot leak through this door."""
    a = secret_fingerprint("aws_access_key", "config/prod.env", 0)
    b = secret_fingerprint("aws_access_key", "config/prod.env", 1)
    assert a != b
    assert len(a) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_fingerprint.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'security'`

- [ ] **Step 3: Write minimal implementation**

```python
# bin/security/__init__.py
```

```python
# bin/security/fingerprint.py
"""Stable identity for a finding.

The fingerprint is what lets a second analysis say "this is the same finding"
instead of reporting everything as new. It deliberately excludes the line
number: a finding that moved because someone added an import above it is the
same finding, and anchoring on the line would resurrect the whole report on
every reformat.
"""

import hashlib
import re

_WHITESPACE = re.compile(r"\s+")


def _normalise(snippet: str) -> str:
    return _WHITESPACE.sub(" ", snippet).strip()


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def fingerprint(category: str, rule: str, path: str, snippet: str) -> str:
    """Identity of a non-secret finding."""
    return _digest(category, rule, path, _normalise(snippet))


def secret_fingerprint(secret_type: str, path: str, ordinal: int) -> str:
    """Identity of a secret finding.

    The secret's value is not a parameter. Hashing it would put an oracle for
    the secret in the ledger -- weak, but real -- so identity comes from where
    it is and which occurrence in that file it is, never from what it says.
    """
    return _digest("secret", secret_type, path, str(ordinal))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/security/test_fingerprint.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add bin/security/__init__.py bin/security/fingerprint.py tests/security/
git commit -m "feat(security): stable fingerprints for findings

A finding keeps its identity across reformatting, so a second analysis
reports what actually changed instead of everything. A secret's value is
never an argument to its fingerprint: hashing it would leave an oracle for
the secret in the ledger."
```

---

## Task 2: Ledger schema and writes

**Files:**
- Create: `bin/security/ledger.py`
- Test: `tests/security/test_ledger.py`

**Interfaces:**
- Consumes: nada de Task 1 (o ledger recebe fingerprints já calculados).
- Produces:
  - `connect(path: Path) -> sqlite3.Connection` — cria o schema se faltar
  - `start_analysis(conn, project, repo, branch, commit_sha, profile, run_id) -> int`
  - `finish_analysis(conn, analysis_id, state, spend_usd=0.0) -> None` com `state` em `{"done","failed","capped"}`
  - `record_finding(conn, analysis_id, finding: dict) -> None` — `finding` tem `fingerprint`, `category`, `rule`, `severity`, `title`, `rationale`, `remediation`, `occurrences: [{"file","line","snippet_hash"}]`
  - `set_decision(conn, project, fingerprint, state, reason, decided_by) -> None` com `state` em `{"accepted","false_positive"}`
  - `decisions_for(conn, project) -> dict[str, dict]`
  - `findings_of(conn, analysis_id) -> list[dict]`
  - `latest_analysis(conn, project, repo, branch, before=None) -> dict | None`

- [ ] **Step 1: Write the failing test**

```python
# tests/security/test_ledger.py
import pytest
from security import ledger


@pytest.fixture
def conn(tmp_path):
    return ledger.connect(tmp_path / "security.db")


def _finding(**over):
    base = {
        "fingerprint": "a" * 64, "category": "sast", "rule": "sql-injection",
        "severity": "high", "title": "String-built SQL", "rationale": "why",
        "remediation": "use parameters",
        "occurrences": [{"file": "app/db.py", "line": 12, "snippet_hash": "h1"}],
    }
    base.update(over)
    return base


def test_a_finding_round_trips_with_its_occurrences(conn):
    aid = ledger.start_analysis(conn, "web", "web", "main", "abc123", "standard", "run-1")
    ledger.record_finding(conn, aid, _finding())
    ledger.finish_analysis(conn, aid, "done", 1.25)

    got = ledger.findings_of(conn, aid)
    assert len(got) == 1
    assert got[0]["rule"] == "sql-injection"
    assert got[0]["occurrences"][0]["file"] == "app/db.py"


def test_a_decision_belongs_to_the_project_not_the_branch(conn):
    ledger.set_decision(conn, "web", "a" * 64, "false_positive", "test fixture", "luiz")
    assert ledger.decisions_for(conn, "web")["a" * 64]["state"] == "false_positive"
    assert ledger.decisions_for(conn, "other") == {}


def test_a_decision_requires_a_reason(conn):
    with pytest.raises(ValueError):
        ledger.set_decision(conn, "web", "a" * 64, "accepted", "   ", "luiz")


def test_latest_analysis_is_scoped_to_repo_and_branch(conn):
    a1 = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.finish_analysis(conn, a1, "done")
    a2 = ledger.start_analysis(conn, "web", "web", "develop", "c2", "standard", "r2")
    ledger.finish_analysis(conn, a2, "done")

    assert ledger.latest_analysis(conn, "web", "web", "main")["id"] == a1
    assert ledger.latest_analysis(conn, "web", "web", "develop")["id"] == a2
    assert ledger.latest_analysis(conn, "web", "web", "nope") is None


def test_a_running_analysis_is_not_the_baseline_for_the_next_one(conn):
    """Only a finished analysis is something to compare against."""
    a1 = ledger.start_analysis(conn, "web", "web", "main", "c1", "standard", "r1")
    ledger.finish_analysis(conn, a1, "done")
    ledger.start_analysis(conn, "web", "web", "main", "c2", "standard", "r2")
    assert ledger.latest_analysis(conn, "web", "web", "main")["id"] == a1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/security/test_ledger.py -v`
Expected: FAIL — `ImportError: cannot import name 'ledger'`

- [ ] **Step 3: Write minimal implementation**

```python
# bin/security/ledger.py
"""Everything that touches data/security.db.

SQLite rather than JSON files because every question the area asks is a query
-- filter by severity, diff two analyses, aggregate posture -- and because the
deterministic phase writes while the page is already reading.
"""

import json
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT NOT NULL, repo TEXT NOT NULL, branch TEXT NOT NULL,
  commit_sha TEXT NOT NULL, profile TEXT NOT NULL,
  started INTEGER NOT NULL, ended INTEGER,
  state TEXT NOT NULL, spend_usd REAL NOT NULL DEFAULT 0,
  run_id TEXT NOT NULL DEFAULT '',
  coverage_note TEXT NOT NULL DEFAULT '');

CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER NOT NULL REFERENCES analysis(id),
  fingerprint TEXT NOT NULL, category TEXT NOT NULL, rule TEXT NOT NULL,
  severity TEXT NOT NULL, title TEXT NOT NULL,
  rationale TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
  partial_note TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS finding_by_analysis ON finding(analysis_id);
CREATE INDEX IF NOT EXISTS finding_by_fp ON finding(fingerprint);

CREATE TABLE IF NOT EXISTS occurrence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER NOT NULL REFERENCES finding(id),
  file TEXT NOT NULL, line INTEGER NOT NULL DEFAULT 0,
  snippet_hash TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS occurrence_by_finding ON occurrence(finding_id);

-- Keyed by project, not by branch: dismissing a false positive on develop and
-- watching it resurrect on main would make the feature unusable.
CREATE TABLE IF NOT EXISTS decision (
  project TEXT NOT NULL, fingerprint TEXT NOT NULL,
  state TEXT NOT NULL, reason TEXT NOT NULL,
  decided_by TEXT NOT NULL DEFAULT '', decided_at INTEGER NOT NULL,
  PRIMARY KEY (project, fingerprint));

CREATE TABLE IF NOT EXISTS sbom (
  project TEXT NOT NULL, repo TEXT NOT NULL, branch TEXT NOT NULL,
  analysis_id INTEGER NOT NULL, document TEXT NOT NULL,
  PRIMARY KEY (project, repo, branch));
"""

DECISION_STATES = ("accepted", "false_positive")
ANALYSIS_END_STATES = ("done", "failed", "capped")


def connect(path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def start_analysis(conn, project, repo, branch, commit_sha, profile, run_id) -> int:
    cur = conn.execute(
        "INSERT INTO analysis (project, repo, branch, commit_sha, profile,"
        " started, state, run_id) VALUES (?,?,?,?,?,?,'running',?)",
        (project, repo, branch, commit_sha, profile, int(time.time()), run_id))
    conn.commit()
    return cur.lastrowid


def finish_analysis(conn, analysis_id, state, spend_usd=0.0, coverage_note="") -> None:
    if state not in ANALYSIS_END_STATES:
        raise ValueError(f"bad analysis state: {state}")
    conn.execute(
        "UPDATE analysis SET ended=?, state=?, spend_usd=?, coverage_note=? WHERE id=?",
        (int(time.time()), state, spend_usd, coverage_note, analysis_id))
    conn.commit()


def record_finding(conn, analysis_id, finding: dict) -> None:
    cur = conn.execute(
        "INSERT INTO finding (analysis_id, fingerprint, category, rule, severity,"
        " title, rationale, remediation, partial_note) VALUES (?,?,?,?,?,?,?,?,?)",
        (analysis_id, finding["fingerprint"], finding["category"], finding["rule"],
         finding["severity"], finding["title"], finding.get("rationale", ""),
         finding.get("remediation", ""), finding.get("partial_note", "")))
    fid = cur.lastrowid
    for occ in finding.get("occurrences", []):
        conn.execute(
            "INSERT INTO occurrence (finding_id, file, line, snippet_hash) VALUES (?,?,?,?)",
            (fid, occ.get("file", ""), int(occ.get("line", 0)), occ.get("snippet_hash", "")))
    conn.commit()


def findings_of(conn, analysis_id) -> list:
    rows = conn.execute(
        "SELECT * FROM finding WHERE analysis_id=? ORDER BY id", (analysis_id,)).fetchall()
    out = []
    for r in rows:
        occ = conn.execute(
            "SELECT file, line, snippet_hash FROM occurrence WHERE finding_id=? ORDER BY id",
            (r["id"],)).fetchall()
        d = dict(r)
        d["occurrences"] = [dict(o) for o in occ]
        out.append(d)
    return out


def set_decision(conn, project, fingerprint, state, reason, decided_by) -> None:
    if state not in DECISION_STATES:
        raise ValueError(f"bad decision state: {state}")
    if not (reason or "").strip():
        # A decision without a written reason is indistinguishable from a
        # mistake three months later, and it outlives every future analysis.
        raise ValueError("a decision needs a reason")
    conn.execute(
        "INSERT INTO decision (project, fingerprint, state, reason, decided_by, decided_at)"
        " VALUES (?,?,?,?,?,?) ON CONFLICT(project, fingerprint) DO UPDATE SET"
        " state=excluded.state, reason=excluded.reason,"
        " decided_by=excluded.decided_by, decided_at=excluded.decided_at",
        (project, fingerprint, state, reason.strip(), decided_by, int(time.time())))
    conn.commit()


def decisions_for(conn, project) -> dict:
    rows = conn.execute("SELECT * FROM decision WHERE project=?", (project,)).fetchall()
    return {r["fingerprint"]: dict(r) for r in rows}


def latest_analysis(conn, project, repo, branch, before=None):
    """The most recent FINISHED analysis of this repo+branch.

    A running analysis is not a baseline: comparing against a half-written set
    of findings would report everything the agent has not reached yet as fixed.
    """
    sql = ("SELECT * FROM analysis WHERE project=? AND repo=? AND branch=?"
           " AND state IN ('done','capped')")
    args = [project, repo, branch]
    if before is not None:
        sql += " AND id < ?"
        args.append(before)
    sql += " ORDER BY id DESC LIMIT 1"
    row = conn.execute(sql, args).fetchone()
    return dict(row) if row else None


def store_sbom(conn, project, repo, branch, analysis_id, document: dict) -> None:
    conn.execute(
        "INSERT INTO sbom (project, repo, branch, analysis_id, document) VALUES (?,?,?,?,?)"
        " ON CONFLICT(project, repo, branch) DO UPDATE SET"
        " analysis_id=excluded.analysis_id, document=excluded.document",
        (project, repo, branch, analysis_id, json.dumps(document)))
    conn.commit()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/security/test_ledger.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add bin/security/ledger.py tests/security/test_ledger.py
git commit -m "feat(security): the ledger that makes the checklist possible

Findings, their occurrences and the human decisions about them, in
data/security.db. Decisions are keyed by project and not by branch --
dismissing a false positive on develop and watching it come back on main
would make the feature unusable. A decision without a written reason is
refused: it outlives every future analysis, and three months later it is
indistinguishable from a mistake."
```
