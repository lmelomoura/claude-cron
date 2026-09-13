# Aceitação com o CLI real: uma análise de segurança em OpenCode

2026-09-13, opencode-ai 1.18.30 real (`AGENTLOOP_OPENCODE_BIN` não definido),
`pdm_ai/glm-5.3-flash`, config e dados de rascunho em `/tmp/acc` (os mesmos
de `acceptance-job.md`). Duas análises: a primeira em `398eb96` (que
encontrou o defeito do `export`, medição 36), a segunda em `c9bb471`, com a
correcção. Nesta máquina não há gitleaks, trivy, semgrep nem syft: a nota de
cobertura diz o que isso deixou por fazer, como deve.

## O rascunho

`/tmp/acc/repo-sec`: um `package.json` com `lodash 4.17.4` e `minimist 1.2.0`
(sem lockfile), um `src/config.js` com a chave de exemplo da documentação da
AWS (`AKIAIOSFODNN7EXAMPLE`), um `README.md`, um remote bare. Em
`projects.json`:

```json
{"name":"acc-sec","cwd":"/tmp/acc/repo-sec","base":"main","worktree":{"enabled":true},
 "security":{"enabled":true,"platform":"opencode","model":"pdm_ai/glm-5.3-flash","max_budget_usd":2}}
```

```bash
AGENTLOOP_CONFIG=/tmp/acc/config AGENTLOOP_DATA=/tmp/acc/data bash bin/agentloop security analyze acc-sec acc-sec main quick
AGENTLOOP_CONFIG=/tmp/acc/config AGENTLOOP_DATA=/tmp/acc/data bash bin/agentloop security list --project acc-sec
AGENTLOOP_CONFIG=/tmp/acc/config AGENTLOOP_DATA=/tmp/acc/data bash bin/agentloop security findings --analysis 2
```

## O ledger

`security list --project acc-sec`, as duas análises:

```json
{"id":2,"state":"done","spend_usd":0.01303070658}
{"id":1,"state":"done","spend_usd":0.026435312931000002}
```

Estado `done` nas duas. A nota de cobertura da análise 2 (a da 1 é a mesma,
seguida do resumo que o agente lhe acrescentou):

> A default noise filter was in effect: findings under a fixtures, __fixtures__
> or testdata directory were not reported, and in files ending .dist, .example,
> .sample or .template — committed templates of a configuration — a generic
> password/token value and an AWS access key were read as placeholders rather
> than leaks. Every other credential shape, a private key included, is still
> reported from a template. Add "!defaults" to the project's ignore_paths to
> scan all of it. Secrets were scanned by the built-in pattern scanner and its 8
> shaped rules, not by gitleaks: a credential whose shape is outside those rules
> would not have been found. No SBOM was recorded for this analysis: neither
> producer had a component to list, so there is no component inventory to
> download for this run. The infrastructure-as-code misconfiguration scan did
> not run (trivy is not available to this analysis) -- there is no built-in
> scanner for this category, so a Dockerfile, Terraform module, Kubernetes
> manifest, Helm chart or CloudFormation template committed to this repository
> was not checked at all this run. The SAST pre-pass did not run (semgrep is
> not available to this analysis) — the SAST pass itself is unaffected, since
> it has always been this category's primary source.

## Os findings

10 findings, os mesmos nas duas análises (fingerprints iguais, as linhas
foram re-reportadas): 1 `secret` (o `aws access token committed to the
repository` de `src/config.js:5`, triado como a chave de exemplo da
documentação: `info` na análise 1, `low` na 2), 1 `hygiene` (`This repository
has no .gitignore`), 8 `dependency` reportados pelo agente a partir dos pins,
já que não há lockfile para a fase OSV (`lodash 4.17.4`: CVE-2019-10744,
CVE-2018-16487, CVE-2020-8203, CVE-2021-23337 `high`, CVE-2018-3721,
CVE-2020-28500 `medium`; `minimist 1.2.0`: CVE-2020-7598, CVE-2021-44906
`medium`).

## O journal e o `tick.log`

As duas linhas do journal (`security-acc-sec` é o job derivado):

```json
{"id":"security-acc-sec","status":"success","cost":0.026435312931000002,"cost_basis":"reported","turns":35,"duration":75,
 "session":"ses_f6683bdc1ffefBcX6PXjI6k2yF","platform":"opencode","model_id":"pdm_ai/glm-5.3-flash",
 "tokens":{"input":736793,"cached":0,"cache_write":0,"output":4306,"reasoning":10807}}
{"id":"security-acc-sec","status":"success","cost":0.01303070658,"cost_basis":"reported","turns":22,"duration":28,
 "session":"ses_f665f8504ffe3KVQHOcIz7Zt53","platform":"opencode","model_id":"pdm_ai/glm-5.3-flash",
 "tokens":{"input":374836,"cached":0,"cache_write":0,"output":2208,"reasoning":2491}}
```

`tick.log` da análise 2:

```
2026-09-13T07:17:05Z security-acc-sec: isolated in /tmp/acc/data/worktrees/security-acc-sec/20260913T071705Z-25241 (cwd /tmp/acc/data/worktrees/security-acc-sec/20260913T071705Z-25241/repo-sec)
2026-09-13T07:17:05Z security-acc-sec: starting run (20260913T071705Z-25241)
2026-09-13T07:17:05Z security-acc-sec: deterministic phase ran before the agent (prepare, 0s) — opencode does not run it inside the agent (prepare_inline)
2026-09-13T07:17:34Z security-acc-sec: finished status=success rc=0 denials=0 cost=$0.01303070658 turns=22 model=pdm_ai/glm-5.3-flash (pdm_ai/glm-5.3-flash) forced=true platform=opencode cost_basis=reported
```

`prepare` correu pelo motor antes do agente (a linha acima; o `.prepare` ao
lado do log tem 1316 bytes); o `.err` de ambos os runs tem 0 bytes.

## O que o agente fez, lido no stream

Análise 1 (35 turnos): `Skill` ×1 (`{"name": "security-analysis"}`), `Read`
×5 (entre eles `<repo>/skills/security-analysis/SKILL.md`, o caminho que o
prompt dá), `Bash` ×17, `Grep` ×3; nenhum `task` (fechado por regra no bloco
de permissões, e o agente não o tentou). Os comandos `agentloop security …`
nos `Bash`, por ordem: `checklist`, `checklist`, `fingerprint`,
`report-finding`, `checklist`, `finish`, `checklist`. Análise 2 (22 turnos):
`Skill` ×1, `Read` ×1 (o `SKILL.md`), `Bash` ×14; `checklist`, `checklist`,
`report-finding` ×3, `checklist`, `finish`, `checklist`. O texto final de
cada uma começa por `RUN COMPLETE: analysis 1 closed done …` / `Analysis 2
closed done …` e resume a triagem (a chave da AWS lida como exemplo, os pins
como dependências vulneráveis).

## O defeito que a análise 1 encontrou

Na análise 1 o `tick.log` trouxe
`opencode export gave no model for session ses_f6683bdc1ffefBcX6PXjI6k2yF — model_id stays the requested id`.
A causa (medição 36, `36-export-pipe-truncation.meta.txt`): através de um
pipe o `opencode export` desta sessão pára aos 65536 bytes (rc 0, JSON
cortado); para um ficheiro são 264607 bytes, com
`info.model = {id: glm-5.3-flash, providerID: pdm_ai, variant: default}`. O
motor passou a ler o `export` e o catálogo através de um ficheiro
(`c9bb471`, com os seus casos de selftest). A análise 2, já com a correcção,
não tem essa linha: o `export` (180330 bytes) foi lido inteiro. O stream da
própria corrida não sofre do mesmo: o `.raw` da análise 1 tem 173232 bytes,
85 eventos, todos parseáveis, o último `step_finish{reason: stop}`, lido pelo
normalizador através do FIFO à medida que o CLI escrevia.
