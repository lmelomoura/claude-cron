# Redesenho da aplicação — Fase 2: Jobs, Runs e Projects

**Data:** 2026-08-23
**Branch:** `feat/security-analysis`
**Estado:** desenho escrito sem revisão por secções — ver «Como este documento foi escrito»

## Como este documento foi escrito

A Fase 1 passou por brainstorm interativo: quatro secções apresentadas uma a
uma, cada uma aprovada antes da seguinte. Esta não passou. O utilizador pediu
para arrancar a Fase 2 e ficou offline.

O que isso significa na prática: as decisões estruturais **não são novas**. Já
foram tomadas e aprovadas na Fase 1 — a divisão em quatro fases e a sua ordem,
`ui/app/` com o contrato de `page.js`, DOM em vez de strings, testes de
caracterização antes de restilizar, uma entrada de CHANGELOG por tarefa. Este
documento aplica-as a três páginas; não reabre nenhuma.

O que **é** novo está reunido em «Decisões que este documento toma sozinho», no
fim, para poder ser lido em trinta segundos e revertido sem desfazer o resto.

## Porquê

O Overview fala a linguagem nova. Jobs, Runs e Projects não. Quem navega entre
elas vê a aplicação mudar de identidade a meio — e o desalinhamento é visível
desde que a Fase 1 aterrou.

São as três páginas de tabela, e são o pedaço mais autocontido do que falta:

| Página | Funções | Linhas |
|---|---:|---:|
| Runs | 7 | 526 |
| Projects | 6 | 194 |
| Jobs (tabela) | 4 | 156 |

`bin/dashboard.html` está em 4932 linhas. Esta fase tira-lhe mais 876 de
renderização, além do que o restyle acrescentar em CSS.

## O que cada página passa a ser

As três partilham a mesma anatomia, que é o ponto — hoje cada uma tem a sua.

**Cabeçalho de página.** Ícone contornado em accent, título, uma frase cinzenta
escrita a partir dos números reais, ações à direita. O mesmo `pageHeader()` que
o Overview usa.

**Cartões KPI**, onde há números que valham um. Quatro no máximo. A regra de um
número por rótulo aplica-se: o segundo número de um par vai no sublabel.

**Barra de filtros.** Pesquisa à esquerda, dropdowns em pill, ações à direita.
As três páginas já têm filtros; hoje cada uma os apresenta à sua maneira.

**Cartão-tabela.** Cabeçalhos de 11px em maiúsculas, linhas de ~62px, células
de duas linhas onde a segunda é contexto cinzento, estado como pill, ações
alinhadas à direita — uma primária e um kebab.

**Rodapé com «Showing X to Y of N» e um pager**, mesmo quando há uma página só.
Runs já tem paginação; Jobs e Projects não têm nada.

### Jobs

Colunas como hoje: Job, Project, Status, Schedule, Last run, Next, Today. Os
KPIs vêm do que a página já sabe — total, ativos, a correr agora, gasto de hoje.

A ordenação por coluna mantém-se, incluindo a regra de que as linhas sem
resposta para a coluna ordenada (um job que nunca correu, um desativado sem
«próximo») vão para o fim em vez de fingirem um valor.

### Runs

Colunas como hoje: When, Job, Project, Status, Duration, Cost, Session.
**Duration e Cost ficam colunas separadas** — o comentário no código explica
porquê, e merece sobreviver: juntá-las já deixou cair a ordenação por custo,
tornando o run mais caro do dia impossível de encontrar numa página de 25.

A pesquisa que entra dentro dos logs mantém-se, e a barra de filtros tem de
dizer que é isso que faz.

### Projects

Colunas como hoje: Project, Jobs, Working directory, Repos, Isolation. Mais
uma coluna **Security**, que o mockup pede e a página não tem, lida do bloco
que a Fase 1 do trabalho de segurança já escreve.

A estrela de favorito mantém-se, e mantém o seu efeito: um projeto favorito
sobe ao topo em Jobs.

## Arquitetura

O padrão não muda. Acrescenta-se:

```
ui/app/chrome.js       pageHeader, kpiCard, filterBar, tableCard, tableFooter
ui/app/jobs-table.js    o segundo consumidor de jobs-domain.js
ui/app/runs.js          a tabela, os filtros, o modal de log
ui/app/projects.js      a tabela e a sua coluna de segurança
```

**`chrome.js` existe por causa de um aviso da revisão final da Fase 1.**
`pageHeader` e `kpiCard` são deliberadamente genéricos e vivem em
`ui/app/overview.js`. Seis páginas a importar peças genéricas de um ficheiro
chamado `overview.js` é um nome a mentir seis vezes. Move-se agora, com um
consumidor, em vez de depois com seis.

**`jobs-table.js` é o segundo consumidor prometido.** A Fase 1 moveu o domínio
de jobs inteiro para `jobs-domain.js` precisamente para que esta fase não
tivesse de o duplicar. Esta é a fase que cobra essa promessa: a tabela lê
`jobFacts` e `visibleJobs` do módulo, e `renderJobs` — a bifurcação entre
cartões e tabela que ficou em `bin/dashboard.html` — desaparece com ela.

**`paintJobFilters` e `initPickers` saem agora.** A correção à spec da Fase 1
registou que ficaram para trás por desenharem a tabela. A tabela move-se nesta
fase, portanto vão com ela.

## Testes

O mesmo portão da Fase 1, pela mesma razão: **testes de caracterização passam à
primeira, portanto o portão não é vê-los falhar — é prová-los falsificáveis.**
Partir o comportamento, ver vermelho, reverter, registar.

Antes de tocar em cada página:

**Jobs** — a ordenação por cada coluna, e as linhas sem resposta a irem para o
fim; o desempate por id que não se inverte com a coluna; os filtros de projeto,
estado e pesquisa a estreitarem o mesmo conjunto; o estado vazio a distinguir
«ainda não há jobs» de «os filtros não deixaram passar nada».

**Runs** — a paginação (a página corrente a recuar quando o filtro encolhe o
conjunto); a pesquisa a alcançar o conteúdo dos logs e não só os nomes; que
estados oferecem Resume, que já está pinado e não se repete; Duration e Cost a
ordenarem independentemente.

**Projects** — a contagem de jobs por projeto; os favoritos; o modo de
isolamento a ler três estados e não dois; a coluna de segurança a distinguir
«desativado» de «ativo mas nunca analisado».

Não se pina aparência: nomes de classes, ordem de markup, contagem de
elementos, texto de rótulos que vão mudar.

## Riscos conhecidos

**O bloco de Runs é o maior e o mais entrelaçado.** `renderLog` e `paintLog`
(191 linhas juntas) desenham o modal de log, que tem um terminal, realce e
seguimento de scroll. O modal não é uma tabela e não faz parte do redesenho —
**move-se sem ser restilizado**, e isso deve ser dito no commit em vez de
descoberto depois.

**`clearRunFilters` tem 104 linhas.** É grande demais para o que o nome promete
e provavelmente faz mais do que limpar. Lê-se antes de mover; se fizer três
coisas, separa-se — mas o comportamento não muda nesta fase.

**A coluna Security em Projects é a única informação nova em toda a fase.**
Tudo o resto é o que já está lá, noutro sítio. Se algo correr mal, é aqui.

## Decisões que este documento toma sozinho

Sem aprovação prévia, porque o utilizador está offline. Cada uma é revertível
isoladamente:

1. **`chrome.js` nasce nesta fase**, levando `pageHeader` e `kpiCard` do
   `overview.js`. Recomendado pela revisão final da Fase 1.
2. **Projects ganha uma coluna Security.** Está no mockup; a página não a tem.
3. **O modal de log move-se sem restyle.** É o único componente que a fase toca
   sem redesenhar, e fá-lo para não inchar o âmbito.
4. **A ordem das tarefas é Jobs → Projects → Runs**, do mais pequeno para o
   maior, para que o padrão esteja estabelecido quando chegar às 526 linhas de
   Runs.

## Fora de âmbito

Os dois editores (Fase 3) e as lacunas do índice Security (Fase 4).

## Verificação

Portões no fim: `pytest`, `claude-cron selftest`, `test/e2e.test.sh`, árvore
limpa, os artefactos construídos no mesmo commit que as fontes.
