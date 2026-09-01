# Plano de implementação — Fase 4: o índice Security

> **Para agentes:** SUB-SKILL OBRIGATÓRIA: usar superpowers:subagent-driven-development (recomendado) ou superpowers:executing-plans para executar este plano tarefa a tarefa. Os passos usam checkbox (`- [ ]`) para acompanhamento.

**Objetivo:** fazer o índice Security bater com o `Security.png` elemento a elemento, repor a tendência de 30 dias como dado servido, eliminar os três últimos selects nativos, e alinhar a mobília dos outros três ecrãs da área com os seus PNGs.

**Arquitetura:** as peças do chrome chegam à área Security **em runtime** pela interface do `CCSecurity.init(...)` (lidas do `CCApp` pelo dashboard) — nunca por import entre bundles, que apontaria a bindings mortos. A tendência volta como série calculada em `bin/security/queries.py` e servida pelo endpoint do índice.

**A regra da fase:** a referência é o PNG em `scratchpad/mockups/` (recuperar do transcript se purgado — o método está no ledger). Cada tarefa visual anexa uma captura lado a lado ao relatório. Nenhuma divergência vira «decisão» fora da secção Decisões da spec.

## Restrições globais

- As de sempre: deps de runtime fixas; `esbuild@0.25.0`; `ui/` sem sinks; tokens no CSS; prosa entregue em inglês (plano/spec em pt-PT); entrada de CHANGELOG por tarefa no mesmo commit; `build/build-ui.sh` antes do `git add`; selftest DEPOIS do commit; branch `feat/security-analysis`.
- **Os testes existentes do índice adaptam a forma, nunca a substância.** Um teste cuja substância não sobreviva à forma nova pára a tarefa e sobe ao coordenador.
- O guard `CC_SECURITY_AGENT` e as escritas por trás do `cli.py` não se tocam — isto é UI e leitura.

---

## Tarefa 1: a ponte do chrome e o cabeçalho

**Ficheiros:** `bin/dashboard.html` (objeto do `CCSecurity.init`), `ui/security/page.js`, `ui/security/index-screen.js`, `ui/security/vocabulary.js` se necessário, `tests/test_page_contract.py`.

- [ ] `pageHeader`, `kpiCard` e `tableFooter` entram no objeto do `CCSecurity.init`, lidos do `CCApp` — atenção ao guard TDZ, que já varre este objeto
- [ ] `ui/security/page.js` declara-os; o índice usa `pageHeader` (escudo, «Security», «Vulnerability analysis across your projects.», ações à direita) no lugar do parágrafo solto
- [ ] Os cinco KPI do PNG via `kpiCard`: Projects/«with security enabled», Total analyses/«across all projects», Critical/«needs immediate attention» (tone err), High/«requires review» (tone warn), Success rate/«analyses completed» (tone ok) — número na primeira linha
- [ ] Os testes do índice que leem `secIndexCards` adaptam a forma; o do traço-não-zero mantém a substância intacta
- [ ] Captura lado a lado com o topo do PNG, dois temas; gates; commit

## Tarefa 2: a série de tendência volta ao servidor

**Ficheiros:** `bin/security/queries.py`, `bin/claude-cron-server` (endpoint do índice), `tests/security/test_queries.py` ou vizinho, `tests/test_security_api.py`.

- [ ] `queries.py` ganha `trend_series(project, days=30)`: open findings por análise concluída no ramo declarado, ordenada no tempo — a computação que existiu e foi apagada, agora com consumidor
- [ ] O payload do índice inclui `trend: [...]` por projeto; teste de API pina a forma e o caso vazio (projeto sem análises → lista vazia, não null implícito)
- [ ] Falsificabilidade: inverter a ordem da série → vermelho
- [ ] Gates; commit

## Tarefa 3: a tabela de projetos com as 8 colunas do PNG

**Ficheiros:** `ui/security/index-screen.js`, `ui/css/` (classes da área), `tests/test_page_contract.py`.

- [ ] Colunas exatamente como o PNG: Project (ícone+nome+badge enabled+descrição em duas linhas), Last analysis (relativo + sub «profile · branch»), Profile (pill), Last run (duração + sub data), Findings (chips crit/high/med + «N total»), Trend (30d) (sparkline `createElementNS` da série da T2), Status (pill Active/Disabled), Actions (View sólido + kebab)
- [ ] Larguras declaradas para as 8 — o teste de larguras da F2 estende-se a esta tabela
- [ ] Rodapé «Showing X to Y of N projects» via `tableFooter`
- [ ] Os cues pinados sobrevivem: capped, branch-fallback visível, never-analysed ≠ nada-aberto
- [ ] A barra de filtros do PNG: Search projects + Status + Profile + Branch + Refresh — filtra a tabela, e diz o que pesquisa
- [ ] Captura lado a lado; gates; commit

## Tarefa 4: Recent analyses e Findings overview como no PNG

**Ficheiros:** `ui/security/index-screen.js`, `ui/css/`, `tests/test_page_contract.py`.

- [ ] Recent analyses: cartão com título+sub+«View all analyses»; tabela Run (#N), Project, Profile (pill), Branch, Findings (chips), Status, Date (duas linhas); rodapé com pager numerado
- [ ] Findings overview (30 days): donut com total ao centro; **legenda com ponto, contagem e percentagem por severidade**; «Top issue categories» (5 maiores, ícone + contagem à direita); «View full report»; seletor de período com o vocabulário do Activity
- [ ] O donut mantém os pinos (Info nunca na cor da pista vazia; o cue de capped)
- [ ] Small-caps e prosa de secção saem; o que a prosa dizia vai a `title`/sublabels
- [ ] Captura lado a lado; gates; commit

## Tarefa 5: os três últimos selects nativos

**Ficheiros:** `bin/dashboard.html` (lançador), `ui/security/` onde os popula, testes.

- [ ] `sec-repo`, `sec-branch`, `sec-profile` → o combo da casa (inputs escondidos mantêm os ids; quem os popula passa a alimentar o combo; quem os lê não muda uma linha)
- [ ] O teste da página sem `<select>`… não existe — criá-lo: a página inteira não contém `<select` (o guard que fecha a classe)
- [ ] Falsificar: repor um select → vermelho; gates; commit

## Tarefa 6: a passagem de mobília nos outros três ecrãs

**Ficheiros:** `ui/security/{project-screen,findings-screen,activity-screen}.js`, CSS.

- [ ] Contra `ProjectDetails.png`, `AllFindings.png`, `FullActivity.png`: cabeçalho de página onde falte, cartões na orientação certa, rodapés de tabela onde o PNG os tenha — **sem** reestruturar além disso
- [ ] Capturas lado a lado dos três; gates; commit

## Tarefa 7: fechar a fase

- [ ] Portões todos; artefactos frescos; spec corrigida contra o que aterrou
- [ ] Revisão final (modelo mais capaz): comparar o índice acabado com `Security.png` **elemento a elemento** e listar qualquer divergência fora de «Decisões»; caminhar os quatro ecrãs nos dois temas; re-falsificar dois guards
- [ ] CHANGELOG da fase lido de ponta a ponta

## Auto-revisão

Cobertura: cada número da secção «estado atual» da spec tem tarefa (1→T1, 2→T1, 3→T3, 4→T2+T3, 5→T3, 6→T4, 7→T4, 8→T4, 9→T4; selects→T5; outros ecrãs→T6). A ponte de runtime evita o import morto entre bundles — o risco arquitetural da fase. O maior risco restante: os testes do índice são muitos e pinam markup antigo; a regra «forma adapta, substância pára a tarefa» é o que impede a adaptação de virar enfraquecimento.
