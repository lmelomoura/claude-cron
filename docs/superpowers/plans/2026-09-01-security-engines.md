# Security Engines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Substituir a detecção artesanal por Gitleaks, Trivy, Syft e Semgrep — como binários **opcionais**, detectados em runtime, com a lacuna declarada quando faltam — mantendo o agente como camada de juízo sobre o que eles produzem.

**Architecture:** Um módulo novo, `bin/security/engines.py`, é a única porta para qualquer binário externo: encontra-o, confirma a versão, corre-o com o output para **ficheiro** (nunca para um stream que o log da run capture), e devolve JSON já purgado dos campos que trazem valores em claro. Cada motor tem um adaptador que traduz esse JSON para o formato de `finding` que o ledger já aceita. `cmd_prepare` passa a preferir o motor e a cair para o detector artesanal quando ele não existe.

**Tech Stack:** Python 3.13 (stdlib apenas — `subprocess`, `json`, `shutil`, `tempfile`), pytest.

## Global Constraints

- **Sem dependências Python novas.** Os motores são binários externos, opcionais.
- **Nenhum valor de segredo chega ao ledger, a um report ou a um log** — nem mascarado. Este bloco é o que mais o ameaça: ver "A regra dos campos proibidos" abaixo.
- **Código, identificadores, docstrings, comentários e mensagens de commit em INGLÊS.** Prosa dos documentos em pt-PT.
- **`CHANGELOG.md` no MESMO commit que o código.** O ficheiro pede-o explicitamente ("in the same change as the code, so the entry is written while the reason is still known"), e o bloco 1 não o fez. O `selftest` falha se o CHANGELOG for mais antigo que o último commit em `bin/`.
- **Severidades:** `("critical", "high", "medium", "low", "info")`, em `report.SEVERITIES`.
- **Categorias:** `secret`, `dependency`, `hygiene`, `sast`, e a nova `iac`. Estão em `diff.DETERMINISTIC_CATEGORIES` e em `cli.FINDING_CATEGORIES` — as duas têm de concordar.
- **Testes:** `rtk proxy python3.13 -m pytest tests/security/ -v`. 477 passam hoje; nenhum pode partir.

### Como ler ficheiros neste repositório — não negociável

**Usa a ferramenta `Read` e `rtk proxy grep`. Nunca `cat`, `head`, `sed -n` ou `grep` directos.** O hook `PreToolUse` reescreve todo o Bash através do `rtk`, que **trunca por desenho** (linhas a 80 caracteres, 200 resultados) sem marcador visível, e cujo sumarizador de pytest devolve **"No tests collected"** em execuções com `-k` ou node-id — que se lê exactamente como uma passagem limpa. Corre sempre os testes como `rtk proxy python3.13 -m pytest` — nesta maquina `python3` e o 3.14 e nao tem pytest instalado. Isto já produziu conclusões falsas sobre este módulo.

### A regra dos campos proibidos

Três dos quatro motores devolvem o conteúdo que encontraram:

| Motor | Campos com valor em claro |
|---|---|
| Gitleaks | `Match`, `Secret` |
| Semgrep | `extra.lines` (a linha de código marcada) |
| Trivy | `Secrets[].Match` (se `--scanners secret` for usado) |

**O adaptador descarta-os na função que faz o parse, antes de qualquer coisa os poder ver** — não no fim, não "antes de gravar". Um `print` de debug entre o parse e a purga é suficiente para os pôr no `.stream.ndjson` da run.

Isto não é hipotético. `data/logs/security-minerva/20260821T063112Z-61093.stream.ndjson` contém hoje um bloco PEM de 1.546 caracteres, porque o agente construiu um mascarador `sed` e nunca o ligou ao pipe. A protecção tem de ser estrutural, não uma instrução.

---

## File Structure

**Criar:**
- `bin/security/engines.py` — descoberta de binários, execução segura, purga dos campos proibidos. Sem dependências dentro do pacote além de `report` (para as severidades).
- `bin/security/adapters.py` — um tradutor por motor, do JSON purgado para `finding`.
- `tests/security/test_engines.py`, `tests/security/test_adapters.py`
- `tests/security/fixtures/engines/` — **capturas genuínas** do output de cada motor, purgadas de valores.

**Modificar:**
- `bin/security/cli.py` — `cmd_prepare` (preferir motor, cair para o artesanal), `FINDING_CATEGORIES` (+`iac`)
- `bin/security/diff.py` — `DETERMINISTIC_CATEGORIES` (+`iac`)
- `bin/security/taxonomy.py` — `RULE_RENAMES` ganha as entradas reais
- `bin/security/secrets.py`, `deps.py` — passam a ser o fallback
- `skills/security-analysis/SKILL.md` — o `coverage_note` por linguagem
- `CHANGELOG.md` — em cada commit

---

### Task 1: O adaptador comum

**Files:**
- Create: `bin/security/engines.py`, `tests/security/test_engines.py`

**Interfaces:**
- Produces: `find(name) -> str | None`, `version_of(name) -> str | None`, `run_json(name, args, cwd, timeout) -> tuple[object | None, str]`, `PURGE: dict[str, tuple[str, ...]]`, `purge(name, data) -> object`.

- [ ] **Step 1: Write the failing test**

```python
# tests/security/test_engines.py
import json
import pytest
from security import engines


def test_a_missing_binary_is_absent_not_an_error():
    assert engines.find("definitely-not-a-real-binary-xyz") is None


def test_purge_strips_the_forbidden_fields_from_gitleaks():
    raw = [{"RuleID": "aws-access-token", "File": "config/prod.env",
            "StartLine": 3, "Entropy": 4.5,
            "Match": "AKIA_THE_ACTUAL_VALUE", "Secret": "AKIA_THE_ACTUAL_VALUE"}]
    clean = engines.purge("gitleaks", raw)
    assert "Match" not in clean[0]
    assert "Secret" not in clean[0]
    assert clean[0]["RuleID"] == "aws-access-token"
    assert clean[0]["StartLine"] == 3


def test_purge_strips_the_code_line_from_semgrep():
    # Semgrep returns the matched source line. A finding ON a credential
    # would carry that credential in `extra.lines`.
    raw = {"results": [{"check_id": "x", "path": "a.py",
                        "start": {"line": 1}, "end": {"line": 1},
                        "extra": {"severity": "WARNING", "lines": "KEY = 'the-value'",
                                  "metadata": {"cwe": ["CWE-327: ..."]}}}]}
    clean = engines.purge("semgrep", raw)
    assert "lines" not in clean["results"][0]["extra"]
    assert clean["results"][0]["extra"]["metadata"]["cwe"] == ["CWE-327: ..."]


def test_purge_leaves_an_unknown_engine_untouched():
    assert engines.purge("nosuch", {"a": 1}) == {"a": 1}


def test_purge_survives_a_shape_it_did_not_expect():
    # A version bump can change the shape. Purge must not crash the whole
    # analysis over it -- but it must also not pass a value through.
    assert engines.purge("gitleaks", {"unexpected": "object"}) is not None
    assert engines.purge("gitleaks", []) == []


def test_run_json_reports_a_missing_binary_as_a_note_not_an_exception(tmp_path):
    data, note = engines.run_json("definitely-not-a-real-binary-xyz", [], tmp_path)
    assert data is None
    assert "definitely-not-a-real-binary-xyz" in note
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rtk proxy python3.13 -m pytest tests/security/test_engines.py -v`
Expected: FAIL — `ModuleNotFoundError` / `ImportError`.

- [ ] **Step 3: Write the implementation**

```python
# bin/security/engines.py
"""The one door to an external scanner binary.

Everything about running someone else's program lives here: finding it,
checking it answers, running it, and -- the part that matters -- throwing
away the fields it returns that carry the thing we promised never to
record.

WHY THE PURGE HAPPENS HERE AND NOT AT THE CALL SITE. Three of the four
engines return the content they matched: Gitleaks puts the credential in
`Match` and `Secret`, Semgrep returns the source line in `extra.lines`,
and Trivy's secret scanner has its own `Match`. If the purge lived in the
adapter, every future adapter would have to remember it, and a debug
`print` between the parse and the purge would be enough to put a
credential into the run's `.stream.ndjson`. That is not hypothetical:
this repository's own logs carry a 1,546-character PEM block, printed by
a masking command the agent built and then never piped through. A
promise that depends on somebody remembering a step is not a promise.

OUTPUT GOES TO A FILE, NEVER TO A PIPE WE PRINT. Each engine is asked to
write JSON to a temporary file. Nothing this module returns has passed
through a stream the run's transcript captures.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

# Engine -> the fields that carry matched content, by the path they sit at.
# "*" means "every element of the top-level list".
PURGE = {
    "gitleaks": ("Match", "Secret"),
    "semgrep": ("lines",),
    "trivy": ("Match",),
}

_TIMEOUT = 600


def find(name: str):
    """The binary's path, or None. Never raises: absence is a normal state."""
    return shutil.which(name)


def version_of(name: str):
    """The engine's own version string, or None if it will not answer.

    An engine that is installed but will not report a version is treated
    as absent by the callers: a parser written against a format that has
    since changed is worse than a phase that declared it did not run.
    """
    path = find(name)
    if not path:
        return None
    for flag in ("--version", "version"):
        try:
            out = subprocess.run([path, flag], capture_output=True, text=True,
                                 timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip().splitlines()[0]
    return None


def _strip(obj, fields):
    """Recursively drop `fields` from every dict in `obj`."""
    if isinstance(obj, dict):
        return {k: _strip(v, fields) for k, v in obj.items() if k not in fields}
    if isinstance(obj, list):
        return [_strip(v, fields) for v in obj]
    return obj


def purge(name: str, data):
    """`data` with the engine's forbidden fields removed, at any depth.

    Recursive on purpose. Gitleaks returns a flat list today and Semgrep
    nests `lines` two levels down, but a version bump can move a field --
    and a purge that only looks where the field is today would silently
    stop purging.
    """
    fields = PURGE.get(name)
    if not fields:
        return data
    return _strip(data, frozenset(fields))


def run_json(name: str, args, cwd, timeout: int = _TIMEOUT):
    """Run the engine and return (purged JSON, note).

    `note` is empty when everything worked and is a sentence for the
    coverage note otherwise. The engine writes its JSON to a temporary
    file that this function names, so no result ever crosses a stream the
    run's log captures.

    Returns (None, note) for every failure: not installed, will not report
    a version, timed out, exited badly, wrote nothing, or wrote something
    that is not JSON. An analysis never dies because a scanner did; it
    says what it could not check.
    """
    path = find(name)
    if not path:
        return None, (f"{name} is not installed, so its phase did not run.")
    version = version_of(name)
    if not version:
        return None, (f"{name} is installed but did not report a version, "
                      f"so its phase was skipped rather than parsed blind.")
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "out.json"
        try:
            proc = subprocess.run([path, *[a.replace("{out}", str(out_file)) for a in args]],
                                  cwd=str(cwd), capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, f"{name} did not finish within {timeout}s and was stopped."
        except OSError as exc:
            return None, f"{name} could not be run: {exc.__class__.__name__}."
        if not out_file.exists():
            # stderr is NOT quoted back: an engine that fails while reading a
            # file can put that file's bytes in its error message.
            return None, (f"{name} exited {proc.returncode} without writing a "
                          f"report, so its phase did not run.")
        try:
            data = json.loads(out_file.read_text())
        except (ValueError, OSError):
            return None, f"{name} wrote a report this version cannot read."
    return purge(name, data), ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `rtk proxy python3.13 -m pytest tests/security/test_engines.py -v`
Expected: PASS, 6 passed

- [ ] **Step 5: Commit, with the CHANGELOG in the same commit**

Acrescenta a `CHANGELOG.md`, em `### Added`:

```markdown
- **External scanners run through one door that cannot leak what they
  found.** Gitleaks returns the credential it matched, Semgrep returns
  the source line, Trivy's secret scanner returns both — and this
  repository's own run logs already carry a 1,546-character private key,
  printed by a masking command the agent wrote and then forgot to pipe
  through. Engines now write their JSON to a file this code names, never
  to a stream the run transcript captures, and the forbidden fields are
  stripped recursively in the function that parses them, not at the call
  sites that would each have to remember.
```

```bash
git add bin/security/engines.py tests/security/test_engines.py CHANGELOG.md
git commit -m "feat(security): one door for external scanners, and it cannot leak"
```

---

### Task 2: Gitleaks substitui o detector de segredos

**Files:**
- Create: `bin/security/adapters.py`, `tests/security/test_adapters.py`, `tests/security/fixtures/engines/gitleaks-dir.json`
- Modify: `bin/security/cli.py` (`cmd_prepare`)

**Interfaces:**
- Consumes: `engines.run_json`, `engines.purge` (Task 1); `fingerprint.secret_fingerprint`.
- Produces: `adapters.gitleaks(data, root) -> list[dict]`, `adapters.SEVERITY_BY_RULE`.

**A fixture tem de ser genuína.** Corre o Gitleaks a sério, guarda o JSON, e **purga os campos `Match` e `Secret` antes de o commitar**. Uma fixture escrita à mão a partir da documentação faz o parser e o teste concordarem um com o outro enquanto ambos discordam da ferramenta — e uma fixture não purgada põe um segredo no repositório.

**Âmbito, medido:** `gitleaks dir .` neste repositório devolve 17 achados, dos quais **15 estão em `.superpowers/`, `__pycache__/` e `data/logs/`** — o Gitleaks varre o filesystem, não o que está versionado. Sem `--config` ou `--exclude`, trocar de motor **piora** o ruído. O adaptador tem de lhe passar os `_SKIP_DIRS` e os `ignore_paths` do projecto.

- [ ] **Step 1: Write the failing test**

```python
# tests/security/test_adapters.py
import json
from pathlib import Path
from security import adapters, fingerprint

FIX = Path(__file__).parent / "fixtures" / "engines"


def test_gitleaks_findings_become_secret_findings():
    data = json.loads((FIX / "gitleaks-dir.json").read_text())
    out = adapters.gitleaks(data, root=".")
    assert out, "the captured fixture must contain at least one finding"
    f = out[0]
    assert f["category"] == "secret"
    assert f["severity"] in ("critical", "high", "medium", "low", "info")
    assert len(f["fingerprint"]) == 64


def test_a_gitleaks_finding_carries_no_value_anywhere():
    # The promise, asserted over the whole record rather than field by
    # field: nothing this adapter emits may contain the matched text.
    data = json.loads((FIX / "gitleaks-dir.json").read_text())
    blob = json.dumps(adapters.gitleaks(data, root="."))
    assert "Secret" not in blob and "Match" not in blob


def test_the_fingerprint_matches_our_own_recipe():
    # A secret's identity is type + path, computed by fingerprint.py --
    # NOT gitleaks' own `Fingerprint` field, which has a different recipe
    # and would break every decision recorded before this change.
    data = json.loads((FIX / "gitleaks-dir.json").read_text())
    f = adapters.gitleaks(data, root=".")[0]
    assert f["fingerprint"] == fingerprint.secret_fingerprint(
        f["rule"], f["occurrences"][0]["file"])


def test_several_hits_of_one_rule_in_one_file_are_one_finding():
    data = [
        {"RuleID": "aws-access-token", "File": "a.env", "StartLine": 3, "Entropy": 4.5},
        {"RuleID": "aws-access-token", "File": "a.env", "StartLine": 9, "Entropy": 4.5},
    ]
    out = adapters.gitleaks(data, root=".")
    assert len(out) == 1
    assert sorted(o["line"] for o in out[0]["occurrences"]) == [3, 9]
```

- [ ] **Step 2: Capture the fixture and run the test**

```bash
gitleaks dir . --report-format json --report-path /tmp/gl.json --no-banner --exit-code 0
python3 -c "
import json
d=json.load(open('/tmp/gl.json'))
for f in d: f.pop('Match',None); f.pop('Secret',None)
json.dump(d[:6], open('tests/security/fixtures/engines/gitleaks-dir.json','w'), indent=2)
"
```

Depois confirma, com os olhos, que o ficheiro não contém nenhum valor. Run: `rtk proxy python3.13 -m pytest tests/security/test_adapters.py -v` → FAIL (`ImportError`).

- [ ] **Step 3: Implement the adapter**

Escreve `bin/security/adapters.py` com `gitleaks(data, root)`. Requisitos:
- Agrupa por `(RuleID, File)` numa só `finding` com várias `occurrences`, como `secrets.py` já faz — o fingerprint é `secret_fingerprint(rule, path)` e não admite mais do que um por par.
- **Usa `fingerprint.secret_fingerprint`, nunca o campo `Fingerprint` do Gitleaks.** A receita é outra; adoptá-la mudaria a identidade de todos os achados existentes.
- `severity` vem de um mapa por regra que tu defines (o Gitleaks não emite severidade). Lê `secrets._RULES` e mantém as severidades que já usamos para as regras equivalentes.
- `title`, `rationale` e `remediation` no registo do módulo — e a remediação de um segredo diz sempre que **apagar a linha não chega, é preciso rodar a credencial**.

- [ ] **Step 4: Wire it into `cmd_prepare`**

Em `cmd_prepare`, antes de `secrets.scan_tree`: se `engines.find("gitleaks")`, corre-o (árvore **e** histórico) e usa o adaptador; senão, cai para `secrets.scan_tree`/`scan_history` e acrescenta ao `coverage_note` que o detector artesanal correu. **Nunca os dois** — dois motores na mesma categoria produzem o mesmo buraco com dois fingerprints.

Passa-lhe o âmbito: os `_SKIP_DIRS` e os `ignore_paths` do projecto.

- [ ] **Step 5: Run the whole suite**

Run: `rtk proxy python3.13 -m pytest tests/security/ -v` → 477 + os novos, nenhum partido.

- [ ] **Step 6: Commit with the CHANGELOG entry**

---

### Task 3: Trivy substitui o inventário e a consulta de CVEs

**Files:**
- Modify: `bin/security/adapters.py`, `bin/security/cli.py`
- Create: `tests/security/fixtures/engines/trivy-fs.json`

**Interfaces:**
- Produces: `adapters.trivy_vulns(data) -> list[dict]`.

**Campos reais, capturados:** `VulnerabilityID`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Severity` (`HIGH`/`MEDIUM`/…), `CweIDs` (lista), `Status`, `Title`, `PrimaryURL`.

- [ ] **Step 1: Write the failing test**

```python
def test_trivy_vulnerabilities_become_dependency_findings():
    data = json.loads((FIX / "trivy-fs.json").read_text())
    out = adapters.trivy_vulns(data)
    assert out
    f = out[0]
    assert f["category"] == "dependency"
    assert f["severity"] in ("critical", "high", "medium", "low", "info")


def test_a_cve_without_a_published_fix_is_marked_not_hidden():
    data = {"Results": [{"Target": "package-lock.json", "Type": "npm",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "x",
            "InstalledVersion": "1.0", "Severity": "HIGH", "Status": "affected",
            "Title": "t"}]}]}
    f = adapters.trivy_vulns(data)[0]
    assert "no fixed version" in f["remediation"].lower()


def test_the_severity_words_map_to_ours():
    for trivy, ours in (("CRITICAL", "critical"), ("HIGH", "high"),
                        ("MEDIUM", "medium"), ("LOW", "low"),
                        ("UNKNOWN", "medium")):
        data = {"Results": [{"Target": "t", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1",
             "Severity": trivy, "Title": "t"}]}]}
        assert adapters.trivy_vulns(data)[0]["severity"] == ours
```

- [ ] **Step 2–6:** capturar a fixture com `trivy fs --format json`, implementar, ligar a `cmd_prepare` (preferir Trivy, cair para `deps.inventory` + `osv.query`), correr a suite, commit com CHANGELOG.

O fingerprint mantém a receita actual — `fingerprint("dependency", vuln_id, source, f"{name}@{version}")` — para que os achados já no ledger não mudem de identidade.

---

### Task 4: Syft substitui o SBOM

**Files:** `bin/security/adapters.py`, `bin/security/cli.py`, fixture `syft-cyclonedx.json`

O Syft emite CycloneDX directamente (`-o cyclonedx-json`), que é o formato que `deps.sbom` já produz. O adaptador é sobretudo uma passagem: valida que o documento tem `components` e devolve-o. Quando o Syft não existe, `deps.sbom` continua a servir.

Teste que interessa: um SBOM do Syft e um do `deps.sbom` são ambos aceites por `ledger.store_sbom` e ambos descarregáveis pelo botão que já existe.

---

### Task 5: Semgrep como pré-passagem de SAST

**Files:** `bin/security/adapters.py`, `bin/security/cli.py`, fixture `semgrep-owasp.json`

**Campos reais:** `check_id`, `path`, `start.line`, `extra.severity` (`ERROR`/`WARNING`/`INFO`), `extra.metadata.cwe` (lista, `"CWE-327: Use of a Broken…"`), `extra.metadata.owasp` (lista com **várias edições**: `A03:2017`, `A02:2021`, `A04:2025`).

Requisitos:
- **`extra.lines` é purgado pela Task 1** — confirma-o num teste aqui também.
- A `rule` **tem de ser um nome do nosso vocabulário**, senão `report-finding` recusa-a. Mapeia pelo CWE: extrai `CWE-327` de `extra.metadata.cwe[0]` e procura-o em `taxonomy.SAST_RULES`. Sem correspondência → `other`, com o `check_id` do Semgrep no `rationale`.
- Do `owasp` extrai **a entrada de 2021**, que é a edição a que a nossa taxonomia mapeia.
- **A cobertura por linguagem entra no `coverage_note`.** Medido: o Semgrep corre 147 regras para Python, 65 para JavaScript e **1 para shell**. Num repositório de shell, "o Semgrep correu" é verdade e é enganador. O `coverage_note` diz quantas regras correram por linguagem.

---

### Task 6: A categoria `iac`

**Files:** `bin/security/diff.py`, `bin/security/cli.py`, `bin/security/adapters.py`, `ui/security/vocabulary.js`

`Misconfigurations` do Trivy → `category: "iac"`. Acrescenta `iac` a `diff.DETERMINISTIC_CATEGORIES` e a `cli.FINDING_CATEGORIES` (as duas têm de concordar), e o rótulo à UI.

**Nota medida:** este repositório não tem Dockerfile, Terraform nem manifestos K8s, portanto o Trivy devolveu 0 misconfigurações. A fixture desta tarefa **tem de vir de um repositório que exercite a funcionalidade** — cria um directório temporário com um `Dockerfile` que viole uma regra conhecida, corre o Trivy sobre ele, e captura.

---

### Task 7: O filtro de ruído por omissão

**Files:** `bin/security/ignores.py`, `bin/security/secrets.py`, `bin/security/adapters.py`

Dois itens que a spec-mãe listou (A4.13 e A4.14):
- **Testes e fixtures suprimidos por omissão**, não só por `ignore_paths` manual.
- **`.example`/`.sample`/`.template` excluídos do scan de segredos.** `hygiene.py` já os exclui; `secrets.py` filtra o *valor* por `_is_placeholder` e não o *ficheiro*, portanto um `.env.example` com um valor de aspecto realista passa.

Ambos se aplicam ao motor **e** ao fallback — o filtro vive em `ignores.py`, que os dois consultam.

---

### Task 8: A primeira renomeação real

> **REORDENADA DURANTE A EXECUÇÃO — esta tarefa é PRÉ-REQUISITO, não seguimento.**
> Foi escrita como última por assumir que a renomeação podia esperar. Não pode.
> A Task 2 mostrou porquê: assim que o Gitleaks está presente, **todas** as
> regras de segredo mudam de nome, e o nome está dentro do fingerprint. Enquanto
> `RULE_RENAMES` estiver vazio, a primeira análise numa máquina com Gitleaks
> reporta cada segredo antigo como `fixed` e o mesmo segredo como `new`, e as
> duas decisões humanas do ledger de desenvolvimento (ambas sobre `private_key`)
> deixam de casar com o que quer que seja.
>
> **Esta tarefa tem de aterrar antes de uma análise real correr com motores.**
> Não depende das Tasks 3–7 e pode ser feita a seguir à 2.

**Files:** `bin/security/taxonomy.py`, `CHANGELOG.md`

As regras de segredos mudam todas de nome quando o Gitleaks substitui `secrets._RULES`: `aws_access_key` → `aws-access-token`, `github_token` → `github-pat`, e assim por diante. **Preenche `RULE_RENAMES` com o mapeamento real**, lendo os `RuleID` que o Gitleaks emite (a captura da Task 2 tem-nos) e emparelhando-os com `secrets._RULES`.

Isto é a primeira utilização real do mecanismo do bloco 1, e é o que o valida. Os quatro testes de `test_taxonomy.py` que hoje são vácuos passam a correr a sério.

Depois de preencher: `claude-cron security migrate-rules` sobre o ledger de desenvolvimento, e confirmar que as duas decisões humanas existentes (ambas sobre `private_key`) continuam a casar.

---

## Self-Review

**Cobertura da spec.** Adaptador comum (T1), os quatro motores (T2–T5), `iac` (T6), filtro de ruído (T7), migração (T8). `fixed_version` está na T3. Licenças ficaram deliberadamente fora, como a spec diz.

**`scope` (dev/runtime) NÃO foi implementado, e fica adiado.** Esta linha dizia que estava na T3 ao lado do `fixed_version`; não está, e não está em lado nenhum — não há coluna no ledger, não há campo no achado, não há nota que o refira. Enviamos o bloco sem ele por quatro razões, todas verificadas: é **aditivo e não correctivo** — nenhum achado fica errado por não o ter, apenas menos anotado; **não é entrada do fingerprint**, por isso acrescentá-lo mais tarde não muda a identidade de nada nem orfaniza decisões; **nenhum documento entregue afirma que existe**, portanto não há promessa a desfazer; e a informação que dá — se um CVE está numa dependência de desenvolvimento ou de produção — é exactamente o género de contexto que a triagem do agente (Job 2 da skill) já escreve na `rationale`. A mesma nota está no âmbito da spec, para que quem a ler a seguir não assuma o contrário.

**O ponto mais frágil, assinalado de propósito.** A Task 2 depende de o adaptador conseguir passar o âmbito ao Gitleaks de forma fiável. A medição mostrou 15 achados em 17 fora de código versionado; se a configuração não pegar, o bloco piora o produto em vez de o melhorar. **Mede o número de achados antes e depois de aplicares o âmbito, e põe os dois números no relatório da tarefa.** Se não descer, para e diz — não sigas para a Task 3.
