# Gate de rate-limit no scheduler — estado e continuação

> **Contexto:** ideia 1 das 6 extraídas de `stablyai/orca` em 2026-08-19. A lista
> completa vive na memória do projecto (`orca-ideas-checklist`). Este documento
> regista **o que já está feito**, **como testar**, e **o que falta** — para uma
> sessão seguinte poder continuar sem redescobrir nada.

**Objectivo:** deixar de acordar runs contra uma janela de utilização esgotada.
Os únicos tectos que o scheduler conhecia eram em dólares; numa subscrição quem
trava é a janela de 5h / 7 dias, e a API já reportava esse número no stream sem
ninguém o ler.

**Branch:** `feat/rate-limit-gate`, cortada de `main`.

---

## O que foi confirmado antes de escrever código

Factos verificados contra `data/index.db` — o executor não precisa de os
reconfirmar, mas precisa de os conhecer:

1. **59 dos últimos 60 runs** já trazem `rate_limit_event` no stream. O dado
   estava em disco e nunca foi lido.
2. Em **127 eventos** analisados, os campos são:
   - `rateLimitType`: `five_hour` | `seven_day`
   - `status`: `allowed` (122×) | `allowed_warning` (5×). **Uma recusa nunca foi
     observada** — o gate trata qualquer coisa que não comece por `allowed` como
     recusa, por precaução, mas isso é código não exercitado por dados reais.
   - `utilization`: 0..1, **presente apenas nos eventos `allowed_warning`**. O
     CLI só avisa a partir de `surpassedThreshold: 0.75`.
   - `resetsAt`: epoch em segundos.
   - `overageStatus: rejected` + `overageDisabledReason: org_level_disabled`.
3. Em **2026-07-30** a janela de 7 dias esteve a 96–98% e o loop continuou a
   lançar runs. É o caso que motiva tudo isto.
4. `overageStatus: rejected` significa que bater no tecto é **paragem seca**, não
   abrandamento. É o que justifica travar em vez de apenas mostrar.

---

## Feito (nesta branch)

- [x] **`rl_capture <streamfile>`** (`bin/claude-cron`) — extrai o último evento
      por janela e faz merge em `data/rate-limits.json`, sob o lock
      `locks/.ratelimit`. Tolera linha truncada (`fromjson?`), e **nunca falha um
      run**: escrita de bookkeeping não pode reportar como partido um run que
      funcionou.
- [x] **`rl_gate`** — imprime uma frase legível e devolve 0 quando o run deve ser
      travado. Regras, por ordem: uma recusa da API vence qualquer número;
      depois `utilization >= RL_STOP_AT`. Uma leitura cuja `resets_at` já passou
      é ignorada — é isto que faz o gate largar sozinho.
- [x] **Ligação ao tick** — o gate corre **antes** dos tectos em dólares (é mais
      barato, e é o tecto que realmente trava). Só para runs agendados: `Run now`
      passa por cima, como já faz com o orçamento e o precheck. Grava
      `last_status: "rate_limited"` e `last_rate_limit: {reason}`.
- [x] **Captura ligada ao fim do run**, onde o stream já é lido para extrair o
      evento `result` — inclusive em runs falhados, porque um run morto **no**
      tecto é o que mais interessa registar.
- [x] **`RL_STOP_AT`** = `CLAUDE_CRON_RATE_LIMIT_STOP_AT`, default `0.95`.
- [x] **Servidor:** `classify_tick` reconhece `usage limit reached` e devolve
      `rate_limited`; novo membro em `TICK_OUTCOMES`.
- [x] **Dashboard:** `rate_limited` na banda de ticks com rótulo próprio
      ("usage window spent") e cor própria — deliberadamente **não** fundido com
      `capped`, porque a acção seguinte é diferente: um tecto em dólares é um
      número que escolheste e podes subir, uma janela gasta é esperar.
- [x] **Testes.** `claude-cron selftest`: 8 asserções novas (bloco "rate limits"),
      **310 passed, 0 failed**. `pytest tests/`: **80 passed** (o teste da banda
      passou a cobrir o novo outcome).

---

## Como testar à mão

O ficheiro só nasce quando um run **termina**. Para exercitar o gate sem esperar:

```bash
jq -n --argjson r "$(( $(date +%s) + 3600 ))" \
  '{seven_day:{status:"allowed_warning",utilization:0.98,resets_at:$r,overage:"rejected",seen_at:0}}' \
  > data/rate-limits.json
```

Depois:

- `bin/claude-cron tick` — o job agendado deve ser saltado, e o `data/tick.log`
  deve trazer `usage limit reached — the seven_day window is 98% used and
  overage is off, so the ceiling is a dead stop — it resets in 59 min`.
- No dashboard, a barra das últimas 24h deve mostrar a fatia **usage window
  spent** (reinicia o servidor de controlo primeiro — o Python é carregado uma
  vez; a página em si é lida do disco a cada pedido).
- `Run now` no mesmo job **tem** de continuar a lançar: o override é intencional.
- Põe `resets_at` no passado e volta a correr o tick — o job deve voltar a
  correr, sem tocar em mais nada. É a prova de que o gate expira sozinho.
- Apaga `data/rate-limits.json` — sem leitura, sem gate.

Voltar ao estado normal: `rm data/rate-limits.json`.

---

## Por fazer

- [x] **Fase 2 — a percentagem antes de gastar.** FEITO em 2026-08-20, branch
      `feat/statusline-rate-limits`. `bin/statusline-rate-limits.sh` lê
      `rate_limits` do payload do statusLine e alimenta o mesmo
      `data/rate-limits.json`.

      **Correcção importante ao que estava escrito aqui:** eu tinha assumido que
      isto podia alimentar-se dos próprios runs. **Não pode.** Medido: o
      statusLine **não é invocado em modo headless** — nem com
      `-p --output-format json` nem com `-p --output-format stream-json
      --verbose`, porque não há linha de estado para desenhar. A fonte são as
      **sessões interactivas do operador**, na mesma conta. Continua a valer a
      pena — trabalhas em Claude Code durante o dia e a frota fica a saber quão
      cheia está a janela sem gastar um token para o descobrir — mas é uma
      propriedade diferente da que este documento prometia.

      Formato confirmado no binário do CLI (2.1.201):
      `rate_limits.{five_hour,seven_day}.{used_percentage (0-100), resets_at}`.
      Guardado normalizado para 0-1, que é o que `rl_gate` lê.

      **Não está activo até tu o ligares.** Em `~/.claude/settings.json`:

      ```json
      "statusLine": { "type": "command",
                      "command": "<checkout>/bin/statusline-rate-limits.sh" }
      ```

      Não toquei nas tuas settings. Imprime `5h 62% · 7d 18%`, portanto continua
      a servir como linha de estado.

- [x] **Bug apanhado por isto:** `rl_gate` lia "status ausente" como recusa da
      API. O statusline reporta utilização sem status nenhum, por isso instalá-lo
      teria travado **todos** os runs agendados numa janela saudável. Só um
      status presente e diferente de `allowed*` conta como esgotado.

- [ ] **Mostrar o estado das janelas no Overview.** Neste momento o operador só
      vê o efeito (a fatia na banda), não a causa. Uma linha com "5h: 62% ·
      reinicia às 17:30 · sem overage" tornava o gate previsível em vez de
      surpreendente. O dado já está em `data/rate-limits.json`; falta o endpoint
      e o cartão.
- [ ] **Distinguir contas.** O ficheiro é global, mas as janelas são por conta
      (`CLAUDE_CRON_CLAUDE_CONFIG_DIR`). Com duas contas, uma leitura de uma
      trava runs da outra. Chavear por config dir quando isso for real.
- [ ] **Exercitar o caminho da recusa.** Nenhum evento com `status` de bloqueio
      foi jamais observado; o ramo existe por precaução. Se algum dia aparecer
      um, capturar o JSON e transformá-lo em fixture.
- [ ] **Limiar por job.** `RL_STOP_AT` é global. Um job de 3 minutos podia
      continuar a correr a 97% enquanto um de 100 minutos já não devia arrancar.
      Requer saber a duração típica por job — o histórico já a tem.

---

## As outras 5 ideias

Estão na memória do projecto (`orca-ideas-checklist`), por ordem de retorno:
2. taxonomia de falhas nomeadas · 3. "precisa de atenção" como estado ·
4. maturidade de testes declarada · 5. notificações · 6. tabela de engines.
