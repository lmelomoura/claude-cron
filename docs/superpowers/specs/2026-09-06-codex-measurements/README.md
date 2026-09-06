# Medições do Codex CLI 0.148.0 — 2026-09-05

Evidência da spec [`../2026-09-06-platforms-anthropic-openai-design.md`](../2026-09-06-platforms-anthropic-openai-design.md).
Tudo aqui foi capturado a correr o CLI, não escrito de memória. Fecha a checklist
que [`../../plans/2026-08-20-codex-engine-probe.md`](../../plans/2026-08-20-codex-engine-probe.md)
deixou em aberto por falta de quota.

Conta: ChatGPT Plus, autenticada com `codex login`. Modelo por omissão do CLI
nesse dia: `gpt-5.6-sol` (lido do rollout, não do stream).

| Ficheiro | Comando | O que prova |
|---|---|---|
| `01-trivial-turn.jsonl` | `codex exec --json --skip-git-repo-check -s read-only -C <dir> 'Reply with exactly: ok' </dev/null` | o evento final de um turno com sucesso é `turn.completed`, com tokens e sem custo; exit 0 |
| `02-tool-use.jsonl` | idem, com um prompt que corre `ls` e lê um ficheiro | `item.started`/`item.completed` de tipo `command_execution` com `command`, `aggregated_output`, `exit_code`, `status`; `agent_message` com `text` |
| `03-resume-same-thread.jsonl` | `codex exec resume --json --skip-git-repo-check <thread_id> 'Reply with exactly: resumed'` | um resume devolve **o mesmo** `thread_id` em `thread.started` |
| `04-unknown-model.jsonl` | `-m gpt-does-not-exist` | `item.completed{type:error}`, depois `error` e `turn.failed` com um JSON embebido `{"status":400,…}`; exit 1 |
| `05a-strict-config-bogus-key.stderr.txt` | `--strict-config -c bogus_key_xyz="x"` | `--strict-config` recusa uma chave `-c` desconhecida; exit 1 sem stream |
| `05b-model-reasoning-effort-low.jsonl` | `--strict-config -c model_reasoning_effort="low"` | a chave de esforço é reconhecida |
| `06-stdin-closed.jsonl` | stdin fechado com `<&-` em vez de `</dev/null` | o run funciona na mesma; a linha de stderr aparece na mesma |
| `07-approval-policy-never.jsonl` | `--strict-config -c approval_policy="never"` | a chave de política de aprovação é reconhecida |
| `08-sandbox-denial-read-only.jsonl` | pedir para escrever um ficheiro em `-s read-only` | **nenhum evento** de negação: o agente diz-o em texto; nem `command_execution` apareceu |
| `09-disable-multi-agent.jsonl` | `--strict-config --disable multi_agent` | a flag é aceite (o rollout não mostra o estado da feature; ver medições em falta na spec) |
| `stderr-every-run.txt` | qualquer run acima | a linha `Reading additional input from stdin...` sai **sempre** em stderr, com `</dev/null` ou `<&-` |
| `models-catalog.stripped.json` | `codex debug models` | o catálogo: slug, nome, descrição, níveis de esforço suportados e por omissão, visibilidade, prioridade, sucessor de um modelo descontinuado, janela de contexto. Os prompts (`model_messages`, `base_instructions`) foram retirados |
| `rollout-sample.stripped.jsonl` | `~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<thread_id>.jsonl` do run 02 e do resume 03 | `turn_context.model` diz o modelo que correu; `token_count.rate_limits` traz `primary` (300 min) e `secondary` (10080 min) com `used_percent` e `resets_at`, `plan_type` e `rate_limit_reached_type`; `session_meta` traz `cli_version` e `model_provider`. Instruções retiradas |
| `codex-exec-help.txt`, `codex-exec-resume-help.txt`, `codex-debug-models-help.txt` | `--help` | as flags que existem. `exec resume` **não** tem `-s` nem `-C` |

Já existia, da Fase 0: [`../../../../test/fixtures/codex-exec-quota-exhausted.jsonl`](../../../../test/fixtures/codex-exec-quota-exhausted.jsonl),
a quota esgotada a chegar como `error` + `turn.failed`, exit 1.

Quando o plano B copiar estes ficheiros para `test/fixtures/codex/`, esta pasta
fica como registo do dia em que foram medidos.
