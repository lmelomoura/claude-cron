# Redesenho da aplicação — Fase 4: o índice Security

**Data:** 2026-08-27
**Branch:** `feat/security-analysis`
**Estado:** desenho escrito com o utilizador presente; as decisões novas estão em «Decisões»

## Porquê, e a regra número um

Esta é a fase onde tudo começou: o utilizador comparou o índice Security com o
mockup `Security.png` e perguntou porque estava diferente. A causa, registada
no ledger, foi eu ter sobre-generalizado uma instrução estreita sobre o
*estilo* dos cartões para licença de redesenhar a arquitetura de informação —
e depois documentar as omissões como decisões. E repeti a classe do erro nos
editores da Fase 3, ao trabalhar da minha descrição dos artboards em vez dos
artboards.

**A regra desta fase: a referência é o pixel do mockup, não prosa nenhuma
sobre ele.** Os quatro PNGs foram recuperados do transcript (tinham
desaparecido de Downloads) e estão em `scratchpad/mockups/`. Cada tarefa
compara o ecrã construído com o PNG lado a lado, e nenhuma divergência se
descreve como decisão sem estar na secção «Decisões» deste documento, aprovada.

## O estado atual contra o `Security.png`

Em falta no índice de hoje, lido do PNG e confirmado no ecrã ao vivo:

1. **Cabeçalho de página** (escudo + «Security» + frase cinzenta) — hoje há um
   parágrafo de prosa solto.
2. **Os cinco cartões KPI na orientação certa** — hoje estão invertidos
   (ícone+rótulo na primeira linha), precisamente a inversão que a Fase 1
   corrigiu no Overview; os dois sistemas de cartões não partilham classes.
3. **Barra de filtros**: pesquisa + Status + Profile + Branch + Refresh à
   direita — hoje não existe.
4. **A tabela de projetos com as 8 colunas do mockup**: Project, Last analysis
   (com sub «profile · branch»), Profile (pill), Last run (duração + data),
   Findings (chips de severidade + «N total»), **Trend (30d)** (sparkline),
   Status, Actions (View sólido + kebab) — hoje tem 5 colunas e falta
   precisamente o resto. **A computação da tendência existiu e foi apagada
   como código morto** quando ninguém a renderizava; esta fase repõe-na.
5. **Rodapé «Showing X to Y of N»** na tabela de projetos — não existe.
6. **Recent analyses como tabela** num cartão com «View all analyses» e pager
   numerado — hoje é outra apresentação.
7. **Findings overview (30 days)**: donut com total ao centro, **legenda com
   contagens e percentagens**, «Top issue categories» com ícones e contagens à
   direita, e «View full report» — hoje o donut não tem legenda com
   percentagens nem o cartão tem o botão.
8. **Títulos de secção em small-caps** que nenhuma outra página usa — saem;
   cada bloco vira um cartão com título normal, como no mockup.
9. **A prosa explicativa a meio da página** desce a tooltips e sublabels.

Fora do índice mas na área: os **três últimos selects nativos do produto**
(`sec-repo`, `sec-branch`, `sec-profile`, no lançador de análises) passam aos
controlos da casa; e os outros três ecrãs (projeto, findings, activity)
recebem uma passagem de mobília contra os seus PNGs — cabeçalho e orientação
dos cartões — sem reestruturação além disso, porque a estrutura deles já veio
dos mockups no redesenho anterior.

## Arquitetura

**A área Security passa a receber as peças do chrome pela sua interface.** O
`ui/security/` é um bundle separado e não pode importar `ui/app/chrome.js`
diretamente — cada bundle tem a sua cópia de `page.js`, e a do security nunca
é ligada pelo `CCApp.init`; os imports partilhados apontariam a bindings
mortos. A via certa já existe: o dashboard constrói o objeto de
`CCSecurity.init(...)`, e passa a incluir `pageHeader`, `kpiCard` e
`tableFooter` **em runtime**, lidos do próprio `CCApp` — uma cópia única a
executar, zero drift, e o guard TDZ cobre o objeto novo como cobre os outros.

**A tendência volta como dado, não como enfeite.** `bin/security/queries.py`
volta a calcular a série de 30 dias por projeto (open findings por análise,
no ramo declarado) e o endpoint do índice entrega-a; a sparkline desenha-a
com `createElementNS`, como as barras que já existem. Teste da série no lado
Python, teste do render no lado Node.

**Os testes existentes do índice.** Pinam semântica de dados (o traço em vez
de 0%, o cue de capped, a branch com fallback visível, o donut que não pinta
Info como pista vazia) e essa semântica **sobrevive intacta** — os testes
adaptam-se à forma nova onde leem markup, com a substância preservada, como o
teste do Info-mais-baixo na conversão dos selects. Nenhum teste se enfraquece;
qualquer um que não possa manter a substância pára a tarefa e sobe.

## Decisões

1. **As colunas Status e Actions do mockup leem o que existe.** Status =
   ativo/desativado da análise por projeto (o que a coluna Security de
   Projects já distingue); Actions = View (abre o projeto) + kebab com o que a
   linha de hoje oferece. Nada de estados novos inventados.
2. **«Last run» é a duração da última análise** (o mockup mostra «2h 15m» com
   a data por baixo) — vem do run journal que o ecrã já lê.
3. **Top issue categories** usa as categorias/regras que o donut de hoje já
   conhece («rules producing the most open findings»), com os cinco maiores.
4. **O period selector do cartão Findings overview** (Last 30 days) fica com
   os períodos do ecrã Activity (7/30/90/all), partilhando o vocabulário.

## Fora de âmbito

Reestruturar os ecrãs de projeto/findings/activity além da passagem de
mobília. O modal de log e os três widgets de formulário (pendentes nomeados).

## Verificação

Os portões habituais, mais um específico da fase: **captura lado a lado com o
PNG em cada tarefa visual**, nos dois temas, anexada ao relatório da tarefa. A
revisão final compara o ecrã acabado com o `Security.png` elemento a elemento
e lista qualquer divergência que não esteja em «Decisões».
