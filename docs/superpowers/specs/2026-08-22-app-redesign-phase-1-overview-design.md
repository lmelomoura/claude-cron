# Redesenho da aplicação — Fase 1: fundação e Overview

**Data:** 2026-08-22
**Branch:** `feat/security-analysis`
**Estado:** implementado; este documento foi corrigido contra o que aterrou —
ver `CHANGELOG.md` para o detalhe de cada tarefa

## Porquê

Os quatro mockups da área Security estabeleceram uma linguagem visual que o resto
da aplicação não fala. As páginas Overview, Jobs, Runs, Projects e os dois
editores continuam com a mobília anterior: parágrafos de introdução acima das
tabelas, números soltos sem cartão, tabelas sem rodapé nem paginação, e nenhuma
barra de filtros consistente.

Não há mockup para essas páginas. A linguagem foi extraída dos quatro que
existem e desenhada nas seis que faltavam, num canvas que o utilizador reviu e
aprovou sem alterações. Este documento é a primeira das quatro fases que a
aplicam.

### As quatro fases

Medido antes de decidir: `bin/dashboard.html` tem 6725 linhas, das quais 1415 de
CSS (789 regras) e 4272 de script (151 funções de topo). Distribuídas por área:

| Área | Funções | Linhas |
|---|---:|---:|
| Overview e cartões de job | 15 | 614 |
| Jobs (tabela) | 5 | 156 |
| Runs | 6 | 489 |
| Projects | 4 | 119 |
| Editores | 15 | 1075 |
| Infraestrutura partilhada | 11 | 667 |
| Helpers diversos | 95 | 1087 |

Mover tudo para módulos, restilizar tudo e fechar as lacunas do índice Security
num só plano é âmbito que rebenta a meio — e rebenta na parte em que já não há
atenção para rever. Daí quatro fases, cada uma com o seu documento e o seu plano:

1. **Fundação e Overview** — este documento
2. **Jobs, Runs, Projects** — as três páginas de tabela
3. **Editores** — job e projeto
4. **Índice Security** — as lacunas contra o mockup original

O comportamento não muda em nenhuma delas. Muda onde a informação é lida, e o
sítio onde o código que a desenha vive.

## Arquitetura

### Onde passa a viver o quê

```
ui/css/tokens.css        as variáveis :root, claro e escuro, tal como são hoje
ui/css/components.css    cabeçalho de página, cartão KPI, barra de filtros,
                         cartão-tabela, rodapé e pager, pills, botões, tabs, rail
ui/css/pages.css         o que é próprio de uma página e não é componente

ui/app/page.js           a interface com a página, no mesmo contrato de
                         ui/security/page.js
ui/app/jobs-domain.js    jobFacts, visibleJobs, os filtros, bulk — sem DOM
ui/app/overview.js       a saudação, a banda de 24h, os KPIs, os cartões de job,
                         os worktrees
ui/app/index.js          bindPage e a superfície que o dashboard chama

bin/static/app.css       artefacto committado, servido por /static/
bin/static/app.js        artefacto committado, irmão de security.js
```

`bin/dashboard.html` fica com o esqueleto HTML, os diálogos, a tabela de ícones
e o script de arranque. Perde as 1415 linhas de CSS e a construção de markup do
Overview (`pulseHtml`, `helloHtml`, `jobCard`), reescrita como DOM em
`ui/app/overview.js` em vez de movida. `renderJobCards` não sobrevive à
reescrita: é eliminada, com o seu markup por-cartão absorvido pelo `jobCard`
já reescrito e a sua chrome de agrupamento (cabeçalhos de projeto, estrela,
botão de bulk) a ficar em `bin/dashboard.html`, ainda construída a partir de
strings, como `renderJobs`.

**Correção ao desenho: nem tudo o que é "domínio de jobs" sai daqui.** Só a
parte sem DOM — `jobFacts`, `visibleJobs`, `bulkOn`, `bulkLabel`,
`clearJobFilters`, `jobProjectNames` — se muda para `ui/app/jobs-domain.js`.
`paintJobFilters`, `renderJobTable`, `initPickers`, `bulkBtn`/`bulkScope` e a
própria `renderJobs` (o cabeçalho de grupo, a estrela, o botão de bulk) ficam
em `bin/dashboard.html`, porque desenham a tabela Jobs — a página que a Fase 2
move — ou constroem markup a partir de nomes de projeto e contagens que a
própria página escolhe, nunca dos campos de um job; chamam de volta para o
módulo pelo nome em vez de duplicar o que ele já sabe.

O bloco `<style>` desaparece por completo. No `<head>` ficam duas coisas no seu
lugar: `<link rel="stylesheet" href="/static/app.css?v=__BUILD__">`, e antes dele
o script de três linhas que resolve o tema (ver «O tema pisca», mais abaixo).

**Como se prova que a mudança é mecânica.** A primeira ideia foi comparar o
conjunto de seletores antes e depois, contra um ficheiro de referência
capturado do `dashboard.html` de hoje — e não sobreviveu ao resto da fase.
Qualquer tarefa seguinte que apague uma regra a sério (o `.st-run`/`.st-on`/
`.st-idle` que a reescrita do cartão de job deixa de calcular, por exemplo)
tem de editar essa referência à mão, e nesse instante uma regressão real e
uma remoção intencional passam a ser a mesma coisa aos olhos do teste: "a
referência mudou para bater com o build novo". Aterrou em vez disso um teste
sem referência guardada: reúne cada classe a que a UI construída realmente
recorre — `class="..."` estático em `dashboard.html`, e as chamadas a
`el()`/`secEl()` e as atribuições a `.className` em `ui/app/*.js` e
`ui/security/*.js` — e verifica cada uma contra o `bin/static/app.css`
*construído*, não contra as fontes. O que continua por ver é o mesmo: uma
regra que se perde na concatenação porque um ficheiro ficou de fora do `cat`.
O que se ganha: nenhum ficheiro para editar à mão a cada tarefa legítima que
apaga uma regra — só três classes ficam sem regra correspondente, cada uma com
uma razão registada em vez de silenciada com uma regra vazia. Uma quarta,
`movable` (a marca do `relocate()` que movia blocos entre o Overview e a sua
própria página), foi encontrada e registada com a mesma disciplina quando este
teste nasceu, mas ficou órfã dias depois, quando as tabs do Overview — e
`relocate()` com elas — saíram (ver «O que sai», abaixo); foi removida ao
fechar esta fase.

### O acoplamento que decide o desenho

`renderJobs()` é uma função só que escolhe entre desenhar cartões (Overview) ou
uma tabela (Jobs). As duas páginas partilham `jobFacts()`, `visibleJobs()` e
`paintJobFilters()`.

Se esta fase levasse apenas o Overview, esse domínio partia-se ao meio ou ficava
duplicado até à Fase 2. Vocabulário duplicado a divergir foi o defeito recorrente
desta branch — `report.STATES` e `SEV_ORDER` custaram várias rondas de revisão.

Por isso a Fase 1 leva o **domínio de jobs inteiro** para `ui/app/jobs-domain.js`,
sem DOM nenhum, e a Fase 2 limita-se a acrescentar o segundo consumidor.

### Como os módulos falam com a página

O padrão já existe e não se inventa nada. `ui/security/page.js` declara uma
interface explícita; o dashboard constrói um objeto e chama `bindPage(cc)`. Um
nome em falta rebenta no bind, não como `undefined is not a function` três ecrãs
adiante.

`ui/app/page.js` segue o mesmo contrato. O bundle é carregado **antes** do script
da página, pela mesma razão que o `security.js` o é: o arranque chama para dentro
dele, portanto tem de estar definido. O bundle só define; não toca no DOM nem lê
nada da página até `init()`.

## O Overview

De cima para baixo:

**Cabeçalho de página.** Ícone, título, e uma frase escrita a partir dos números
reais — é o que `helloHtml()` já faz, a passar da linha solta para o cabeçalho. À
direita, Refresh e New job.

**Cinco cartões KPI:** Checks, Woke a run, Warnings, Errors, Spent today.
Substituem os três tiles soltos e a barra de rodapé com Today / 7 days /
warnings / errors. Cada cartão leva um número e um sublabel curto; o segundo
número de um par vai no sublabel, nunca ao lado do primeiro.

Warnings e Errors continuam a ser portas: hoje carregam `data-statfilter` e levam
para Runs filtrado. Mantém-se — o cartão fica clicável quando tem destino e
inerte quando o número é zero.

**A banda de 24 horas a toda a largura**, com a legenda por baixo. É uma série
temporal, ganha com largura, e não tem par a competir por ela.

**Os cartões de job**, agrupados por projeto, com o cabeçalho de grupo e as
estrelas de favorito que já existem. A informação é a mesma; a mobília é nova:
raio e sombra dos cartões-tabela, estado como pill em vez de texto colorido, os
seis papéis tipográficos, e a barra de gasto com o tratamento das barras de
progresso do vocabulário. A sparkline, as contagens da sondagem, o backoff e o
aviso de sessão guardada ficam como estão em substância.

### O que sai

**As tabs Jobs / Runs / Worktrees do Overview.** Jobs e Runs são páginas do
sidebar; a tab duplicava-as. Worktrees passa a um cartão que só aparece quando há
diretórios em disco — hoje a tab está sempre presente, a dizer que não há nada.

**Os dois parágrafos `paneblurb`.** O que dizem passa à frase do cabeçalho.

Nenhum número muda. Muda onde é lido.

### Onde isto diverge do artboard `Main.dc.html`

O mockup aprovado — a origem desta secção, comparado agora contra o que
aterrou — desenha a Overview como cabeçalho + cinco KPIs + uma linha a duas
colunas: a banda de 24 horas à esquerda e, à direita, um rail com dois
cartões, "Spend" (duas barras de progresso, hoje e 7 dias, cada uma contra o
seu teto) e "Worktrees on disk" (a lista, com um botão "Manage worktrees") —
seguida de um cartão "Recent runs" com uma tabela paginada. Não há cartão de
job nenhum nesse desenho.

Três afastamentos, todos deliberados:

1. **A banda fica sozinha, a toda a largura — sem rail ao lado.** É a frase
   acima, "não tem par a competir por ela": o par que o mockup lhe dava,
   Spend e Worktrees, não sobrevive a uma Overview com jobs a sério (o
   mockup tem quatro; uma instalação real tem mais, e a banda precisa da
   largura inteira para continuar legível).
2. **Não há tabela "Recent runs" na Overview.** Runs já é uma página do
   sidebar — repeti-la aqui seria a mesma duplicação de domínio que este
   documento evita ao levar `jobFacts`/`visibleJobs` inteiros para
   `ui/app/jobs-domain.js` (ver «O acoplamento que decide o desenho»,
   acima). O espaço que a tabela ocupa no mockup é, na Overview real, os
   cartões de job agrupados por projeto — a peça central deste documento,
   que o mockup não desenhava.
3. **Worktrees é um cartão entre os cartões de job, não um item de rail.**
   Sem rail para o alojar, `worktreesCard` (ver acima) fica depois da
   grelha de jobs, na mesma coluna, e só quando há algo em disco — `null`
   quando não há.

Uma quarta diferença, pequena e **não deliberada**: o mockup dá a "Woke a
run" o verde de sucesso (`--ok`) que "Checks" e "Spent today" não têm;
`kpiCard`, tal como aterrou, não distingue as três — ficam com o mesmo
quadrado accent/roxo, porque nenhuma é uma porta (`door`) com tom próprio
como Warnings/Errors. Não é uma decisão de design, é uma diferença que
ninguém decidiu e que ninguém corrigiu; fica registada para quem for à
Fase 2.

## A regra do DOM

A área Security tem uma proibição de construir DOM a partir de strings HTML,
aplicada por `test_the_security_ui_never_builds_dom_from_html_strings`. Esta fase
estende-a a `ui/app/`.

**Correção ao desenho: a extensão não pediu lógica nova.** `_security_sources()`,
a função de que esse teste já depende para encontrar o que examinar, já
percorria tudo o que está debaixo de `ui/` — `ui/app/` ficou coberto no
instante em que a pasta passou a existir, antes de qualquer linha de
`overview.js` ser escrita. O único ficheiro a mudar foi o próprio teste, cujo
nome dizia "security" a mais: passou a chamar-se
`test_the_built_ui_never_builds_dom_from_html_strings`.

O Overview tem a mesma exposição que a motivou: `checkList()` renderiza a saída
de um script de sondagem arbitrário, e os nomes de tickets vêm do Jira. Hoje isso
está tratado por `esc()`, corretamente — mas por disciplina, e a disciplina é o
que falha.

O custo aparente é reescrever as 164 linhas de `jobCard`. O custo real é zero: o
`jobCard` vai ser reescrito de qualquer maneira, porque é isso a restilização. É
a mesma reescrita, feita da forma que elimina a classe de bug em vez de a manter
viável.

**Isto também fecha a porta a um "mover sem tocar".** A proibição aplica-se a
*todo* o `ui/`, não só ao que se escreve de novo — por isso `pulseHtml`,
`helloHtml`, `jobCard`, `renderJobCards` e `renderRetained` acendem vermelho no
instante em que chegam a `ui/app/`, movidas tal e qual. Não há sequência em que
o Overview se mude primeiro "pixel a pixel", com os testes da secção seguinte
como prova, e só depois se reescreva `jobCard` em DOM — essa ordem foi a
intenção inicial e não podia correr. O que aterrou: só as funções sem sink se
movem inalteradas; `pulseHtml`, `helloHtml`, `jobCard` e `renderRetained` são
reescritas como construtores de DOM, nunca movidas em string, e são os dez
testes da secção seguinte — não uma comparação byte a byte — que garantem que
nada mudou por baixo da reescrita.

## Testes

Escritos **antes** de tocar em cada peça. Pinam dados e comportamento, nunca
aparência.

Os KPIs e a banda:

1. Os cinco KPIs saem dos números certos, de um `tick.log` e um journal conhecidos
2. Uma percentagem sem denominador é `—`, nunca `0%` — a regra que `pct()` já
   aplica dentro de `pulseHtml`, hoje sem teste
3. Os cartões de warnings e errors navegam para Runs filtrado, e ficam inertes a zero
4. Sem checks, a banda diz qual dos quatro vazios é: sem jobs, todos desativados,
   N de M desativados, ou todos ativos

Os cartões de job:

5. A sondagem tem três veredictos, não dois — exit 0, exit 1, e qualquer outro é
   falha. É um bug já corrigido no código e sem teste que o segure.
6. A barra de gasto marca `near` a 80% ou mais, e `over` quando o teto foi atingido
7. Os favoritos vêm primeiro no agrupamento; sem projetos nenhuns, grelha plana
8. O estado vazio distingue "ainda não há jobs" de "os filtros não deixaram passar nada"
9. O backoff diz o multiplicador e quantas corridas falharam
10. "no matching window" e "quando a janela reabrir" são casos distintos

E dois que estendem redes existentes a `ui/app/`: todo o `$("id")` alcançado
existe no HTML, e o JavaScript parseia.

O harness é o que os testes do Security já usam: extrair as funções do bundle,
um DOM mínimo, correr sob Node, asserir a saída. Guardado por
`@pytest.mark.skipif(not shutil.which("node"))`, como os outros.

### O que deliberadamente não se pina

Nomes de classes visuais, ordem do markup, contagem de elementos, e o texto de
rótulos que vão mudar. Um teste que asserta aquilo que o redesenho existe para
mudar tem de ser reescrito ao mesmo tempo que o código — é um teste que não pode
falhar de forma útil, e essa foi uma falha recorrente nesta branch.

## Build e frescura

`build/build-ui.sh` passa a construir três artefactos e a stampar os três:
`security.js`, `app.js` e `app.css`.

**Um digest de fontes partilhado, não um por artefacto.** `build/ui-digest.sh` já
cobre todos os ficheiros sob `ui/`, portanto acrescentar `ui/app/` e `ui/css/`
faz o digest do `security.js` mudar quando o Overview é editado. Isso obriga a
reconstruir os três de uma vez, o que o `build-ui.sh` faz num só comando de
qualquer forma. Um rebuild a mais é barato; um bundle obsoleto a passar a verde
não é.

**Os stamps em CSS.** CSS não tem comentários `//`.

**Correção ao desenho: não ficaram duas formas, ficou uma só.** Ensinar
`build/ui-bundle-digest.sh` a aceitar *também* a forma de bloco ao lado da `//`
que já tinha teria deixado duas grafias para três leitores concordarem —
`build/build-ui.sh` a escrever, `build/ui-bundle-digest.sh` a despir antes de
calcular o hash, e o selftest a ler de volta — e um dos três candidato a
esquecer a segunda forma no próximo artefacto. Os dois stamps, em `security.js`,
`app.js` e `app.css` por igual, passam antes para a forma de bloco:
`/* ui-sources: <sha256> */` e `/* ui-bundle: <sha256> */`, válida em
JavaScript e em CSS, com a mesma regra de exatamente-um-de-cada que já
aplicava. Um formato, não dois.

### Dois bugs latentes que esta mudança ativaria

**O build id não vê CSS.** `_build_id()` faz `STATIC_DIR.glob("*.js")` — só
JavaScript. Um `app.css` alterado não mudaria o `?v=`, e uma tab aberta serviria
o CSS antigo indefinidamente. A correção liga-o à tabela que já decide o que é
servido: iterar os ficheiros cujo sufixo está em `STATIC_TYPES`, em vez de manter
um glob à parte. Uma fonte de verdade, e as duas não voltam a divergir.

**O tema pisca.** `applyTheme(themePref())` corre no script do fim do body e lê o
`localStorage`; até lá o CSS está no tema claro. Com 6725 linhas de página e
93 KB de bundle antes desse ponto, um utilizador em modo escuro apanha um flash
branco — hoje, antes desta mudança. Três linhas no `<head>`, antes da folha de
estilos, que ponham `data-theme` a partir do `localStorage`, resolvem-no.

Esse arranjo é o que permite ao CSS sair inteiro do ficheiro. Sem ele os tokens
teriam de ficar inline **e** em `ui/css/tokens.css` — exatamente o vocabulário
duplicado a divergir que este desenho evita.

## Fora de âmbito

As páginas Jobs, Runs, Projects e os editores mantêm o aspeto atual. Vão parecer
desalinhadas do Overview durante as fases 2 e 3. É o preço da decomposição, e é
visível.

As lacunas do índice Security — cabeçalho de página, barra de filtros, as cinco
colunas em falta incluindo a coluna de tendência a repor, paginação, análises
recentes como tabela, legenda do donut e os botões View — ficam para a Fase 4.

## Verificação

Portões no fim da fase, todos verdes:

- `pytest` — a suite atual mais os testes novos
- `claude-cron selftest` — incluindo a frescura dos três artefactos
- os testes e2e
- árvore limpa, com os três artefactos construídos no mesmo commit que as fontes
