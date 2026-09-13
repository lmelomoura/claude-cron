# Aceitação com o CLI real: um job em OpenCode, de ponta a ponta

2026-09-13, opencode-ai 1.18.30 em `/opt/homebrew/bin/opencode` (o CLI real:
`AGENTLOOP_OPENCODE_BIN` **não** definido), modelo `pdm_ai/glm-5.3-flash`
(pago, no catálogo do CLI), motor na branch `feat/opencode-engine` em
`398eb96`, depois `c9bb471` para a repetição da análise. Config e dados de
rascunho em `/tmp/acc`; nunca `config/` nem `data/` reais.

## O rascunho

`/tmp/acc/config/platforms.json` liga só o `opencode`, com
`pdm_ai/glm-5.3-flash`; `jobs.json` com dois jobs em `opencode`,
`pdm_ai/glm-5.3-flash`, `effort: high`, `full-access`, `max_budget_usd: 1`:

- `acc-oc`, projecto `acc` (`worktree.enabled: false`, cwd `/tmp/acc/repo`, um
  repositório git com um `README.md` e um commit `seed`), prompt "Read
  README.md, then create NOTES.md with one line summarising it, commit it with
  the message 'acceptance', and finish with RUN COMPLETE: <what you did>".
- `acc-oc-open`, projecto `acc-wt` (`worktree.enabled: true`, cwd
  `/tmp/acc/repo-open`, com um remote bare), prompt "Reply with exactly: I did
  some work." (acaba sem declarar o fim: o run fica aberto para o resume).

```bash
AGENTLOOP_CONFIG=/tmp/acc/config AGENTLOOP_DATA=/tmp/acc/data bash bin/agentloop resolve-models opencode
AGENTLOOP_CONFIG=/tmp/acc/config AGENTLOOP_DATA=/tmp/acc/data bash bin/agentloop run acc-oc
AGENTLOOP_CONFIG=/tmp/acc/config AGENTLOOP_DATA=/tmp/acc/data bash bin/agentloop run acc-oc-open
AGENTLOOP_CONFIG=/tmp/acc/config AGENTLOOP_DATA=/tmp/acc/data bash bin/agentloop resume acc-oc-open ses_f6680d377ffecyZ2NdDDBC8toY
```

## O catálogo

`resolve-models opencode` contra o CLI real: 13 modelos (7 `opencode/*-free`,
6 `pdm_ai/*`), `source: "opencode models --verbose"`, `version: "1.18.30"`; o
bloco do modelo usado:

```json
{"id":"pdm_ai/glm-5.3-flash","provider":"pdm_ai","priced":true,
 "cost":{"input":0.033011,"output":0.139816,"cache_read":0.0,"cache_write":0.0},
 "variants":["max","high","non-think"],"tools":true}
```

## O run `acc-oc`

A linha do journal (`tail -1 /tmp/acc/data/runs.ndjson`), lida como pedido:
`status: success`, `platform: opencode`, `cost_basis: reported`, custo na
ordem de `0.00N`, `model_id` igual ao pedido, `session` a começar por `ses_`:

```json
{"id":"acc-oc","status":"success","start":1789281326,"end":1789281331,"duration":5,
 "cost":0.0018640076180000001,"turns":4,"session":"ses_f6685a8efffeOu4UbPEHMrR7IF",
 "log":"/tmp/acc/data/logs/acc-oc/20260913T063526Z-38894.json","note":"","forced":true,
 "precheck":"","project":"acc","model":"pdm_ai/glm-5.3-flash","model_id":"pdm_ai/glm-5.3-flash",
 "resumed_from":"","cause":"","platform":"opencode","cost_basis":"reported",
 "tokens":{"input":55814,"cached":0,"cache_write":0,"output":136,"reasoning":18}}
```

As primeiras cinco linhas do stream normalizado (`init` primeiro, com a
sessão, o modelo, a plataforma, o modo e o cwd; depois `Read`, o seu
resultado, `Write` e o seu resultado; o `Bash` do commit vem a seguir):

```
{"type": "system", "subtype": "init", "session_id": "ses_f6685a8efffeOu4UbPEHMrR7IF", "model": "pdm_ai/glm-5.3-flash", "platform": "opencode", "permissionMode": "full-access", "cwd": "/tmp/acc/repo", "tools": []}
{"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "chatcmpl-tool-a2c5223a3456027a", "name": "Read", "input": {"filePath": "/private/tmp/acc/repo/README.md"}}]}, "session_id": "ses_f6685a8efffeOu4UbPEHMrR7IF"}
{"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "chatcmpl-tool-a2c5223a3456027a", "content": "<path>/private/tmp/acc/repo/README.md</path>\n<type>file</type>\n<content>\n1: # acc\n2: \n3: A throwaway repository for the OpenCode acceptance run.\n4: It has one file, this README, and nothing else.\n\n(End of file - total 4 lines)\n</content>", "is_error": false}]}, "session_id": "ses_f6685a8efffeOu4UbPEHMrR7IF"}
{"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "chatcmpl-tool-8d371430ef955759", "name": "Write", "input": {"content": "acc: a throwaway repository for the OpenCode acceptance run containing only this README.\n", "filePath": "/private/tmp/acc/repo/NOTES.md"}}]}, "session_id": "ses_f6685a8efffeOu4UbPEHMrR7IF"}
{"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "chatcmpl-tool-8d371430ef955759", "content": "Wrote file successfully.", "is_error": false}]}, "session_id": "ses_f6685a8efffeOu4UbPEHMrR7IF"}
```

As últimas duas (o texto final e o `result`, com `tokens`, o custo reportado
e `api_error_status: null`):

```
{"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "RUN COMPLETE: Li o README.md, criei o NOTES.md com um resumo de uma linha e fiz o commit com a mensagem \"acceptance\" (b06190b)."}]}, "session_id": "ses_f6685a8efffeOu4UbPEHMrR7IF"}
{"type": "result", "session_id": "ses_f6685a8efffeOu4UbPEHMrR7IF", "platform": "opencode", "num_turns": 4, "permission_denials": [], "usage": {"input_tokens": 55814, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "output_tokens": 154}, "subtype": "success", "is_error": false, "result": "RUN COMPLETE: Li o README.md, criei o NOTES.md com um resumo de uma linha e fiz o commit com a mensagem \"acceptance\" (b06190b).", "total_cost_usd": 0.0018640076180000001, "cost_basis": "reported", "tokens": {"input": 55814, "cached": 0, "cache_write": 0, "output": 136, "reasoning": 18}, "api_error_status": null}
```

O que mais se leu:

- `.raw` ao lado: 12 eventos (`step_start` ×4, `tool_use` ×3, `step_finish`
  ×4, `text` ×1), o último `step_finish{reason: stop}`; os quatro custos por
  passo `0.000461385212 + 0.000465814535 + 0.000466379568 + 0.000470428303`.
- `.err`: 0 bytes (um run limpo não escreve nada).
- `tick.log`: `starting run` e `finished status=success rc=0 denials=0 …
  platform=opencode cost_basis=reported`, nada mais.
- No repositório: `NOTES.md` ("acc: a throwaway repository for the OpenCode
  acceptance run containing only this README.") e `git log --oneline -2` →
  `b06190b acceptance`, `49c506b seed`.
- `opencode export ses_f6685a8efffeOu4UbPEHMrR7IF` (19395 bytes):
  `info.model = {id: glm-5.3-flash, providerID: pdm_ai, variant: high}`: o
  modelo que correu é o pedido, e o `--variant high` do `effort` chegou.

**Um defeito lido aqui, corrigido em `c9bb471`:** a soma dos quatro custos em
vírgula flutuante deu `0.0018640076180000001`, e era isso que o journal, o
`tick.log` e o `result` traziam. Os números do CLI têm 12 casas; a soma passa
a ser arredondada às mesmas 12 (`0.001864007618`), com o seu teste em
`tests/test_opencode_stream.py`. A segunda análise de segurança, já com a
correcção, registou `0.01303070658`.

## O run aberto e o resume, `acc-oc-open`

O run (o CLI real; a resposta fixa não declara o fim):

```json
{"id":"acc-oc-open","status":"warning","cost":0.000459734582,"cost_basis":"reported","turns":1,
 "session":"ses_f6680d377ffecyZ2NdDDBC8toY","resumed_from":"","platform":"opencode",
 "model_id":"pdm_ai/glm-5.3-flash","note":"UNDECLARED ENDING: the agent stopped without saying its run was finished …"}
```

O directório ficou retido, `/tmp/acc/data/worktrees/acc-oc-open/20260913T064043Z-43678/`,
com `.session` = `ses_f6680d377ffecyZ2NdDDBC8toY` e `.ended` = `open`.

O resume, com o CLI real, na mesma sessão e no mesmo directório (`--dir` é a
worktree retida; medição 08c: noutro directório o CLI pendura para sempre):

```
2026-09-13T06:41:29Z acc-oc-open: resumed ses_f6680d377ffecyZ2NdDDBC8toY in its own tree /tmp/acc/data/worktrees/acc-oc-open/20260913T064043Z-43678 (cwd /tmp/acc/data/worktrees/acc-oc-open/20260913T064043Z-43678/repo-open)
2026-09-13T06:41:29Z acc-oc-open: starting run (20260913T064128Z-46644)
2026-09-13T06:41:32Z acc-oc-open: finished status=warning rc=0 denials=0 cost=$0.000953471214 turns=2 model=pdm_ai/glm-5.3-flash (pdm_ai/glm-5.3-flash) forced=true platform=opencode cost_basis=reported — NOTHING TO DO: No task was ever assigned; the previous run only sent a fixed test reply ("I did some work."), the working tree is clean at the seed commit, and there is no ticket or pending work to resume.
```

```json
{"id":"acc-oc-open","status":"warning","cost":0.000953471214,"cost_basis":"reported","turns":2,
 "session":"ses_f6680d377ffecyZ2NdDDBC8toY","resumed_from":"ses_f6680d377ffecyZ2NdDDBC8toY",
 "platform":"opencode","model_id":"pdm_ai/glm-5.3-flash","note":"NOTHING TO DO: No task was ever assigned; the previous run only sent a fixed test reply (\"I did some work.\") …"}
```

O stream do resume começa pelo `init` com a **mesma** sessão e o cwd da
worktree retida, o modelo lembra-se do turno anterior ("the previous run only
sent a fixed test reply"), corre um `Bash` (`git status && git log`), declara
`NOTHING TO DO`, e o run fecha com `result`; o directório retido foi removido
a seguir (`ls /tmp/acc/data/worktrees/acc-oc-open/` vazio). `.err` de ambos os
runs: 0 bytes.
