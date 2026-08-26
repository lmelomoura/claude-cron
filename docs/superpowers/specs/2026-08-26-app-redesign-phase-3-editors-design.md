# Redesenho da aplicação — Fase 3: os editores

**Data:** 2026-08-26
**Branch:** `feat/security-analysis`
**Estado:** implementado e revisto; corrigido contra o que aterrou

## Porquê

As quatro páginas falam a linguagem nova. Os dois editores — o de job e o de
projeto — ainda têm a mobília antiga: controlos desalinhados, ajuda em
parágrafo, tabs de outro estilo. Os artboards aprovados (`JobEditor.dc.html`,
`ProjectEditor.dc.html`) mostram o destino: controlos de 40px, raio 9px, uma
linha cinzenta de ajuda por campo, rodapé com a ação destrutiva na ponta
esquerda, o mesmo strip de tabs das páginas.

Medido com o método correto (corpo de função por chavetas, não o script que
errou duas vezes):

| Área | Funções | Linhas |
|---|---:|---:|
| Editor de job (`openEditor`, `fill`, `readForm`, os `paint*`…) | 20 | 190 |
| Editor de projeto (`openProjectEditor`, repos, validação…) | 8 | 163 |
| Infra de formulário (`makeWizard`, `makePicker`, `createCombo`…) | 11 | 514 |
| Markup estático dos dois dialogs | — | 356 |

## O pré-requisito: o contrato de render

A revisão final da Fase 2 exigiu-o antes de mover o primeiro editor, e a
investigação mostrou que **o contrato já existe por construção**: o `render()`
do poll de 5 segundos repinta as views e nunca alcança um `<dialog>`. Os
editores são markup estático preenchido por `fill()` ao abrir; o estado por
gravar vive fora do alcance do poll.

O trabalho desta fase não é inventá-lo — é **declará-lo e guardá-lo**:

> O `render()` e tudo o que ele chama tocam apenas nas subárvores das views.
> Um `<dialog>` é montado uma vez, preenchido ao abrir, e nada dentro de um
> dialog aberto é repintado pelo poll.

Um teste passa a impor isto: o corpo de `render()` e dos renderers que chama
não pode conter `$("…")` de nenhum id que viva dentro de um `<dialog>`, nem
seletores que lá cheguem. Falsificável: apontar um repaint a um id de dialog
e ver vermelho.

## O que a fase faz

**1. Pinar o comportamento dos editores** antes de tocar em qualquer coisa,
com o portão de falsificabilidade das fases anteriores. O que se pina:

- `edIsDirty`/`edSnapshot` — o rasto de alterações: um formulário aberto e
  intocado não avisa; um campo mudado avisa; gravar limpa o aviso
- o modo duplo do editor de job: **wizard numerado a criar, tabs planas a
  editar** — mesmo painel, duas navegações
- a validação por passo do editor de projeto (`validateProjectStep`) recusa
  avançar com o passo inválido e diz porquê
- `getDays`/`getEffort`/`effortGet`/`effortSet` — o mapeamento formulário↔job
- o editor de projeto envia **sempre o bloco `security` inteiro com um
  booleano real** — já pinado por teste existente; confirma-se, não se repete

**2. Restilizar os dois dialogs no sítio.** O markup estático (356 linhas em
`bin/dashboard.html`) ganha a mobília dos artboards; o CSS novo vai para
`ui/css/pages.css` (secção própria de formulários) usando apenas tokens. A
regra de sinks aplica-se a `ui/`, não ao markup estático da página — nada
disto a viola.

**3. Mover só a parte pura para `ui/app/editor-domain.js`**: `edSnapshot`,
`edIsDirty`, `validateProjectStep`, `getDays`, `getEffort`, `effortGet`,
`effortSet`, `collectRepos`. São mapeamento e decisão, sem DOM — testáveis sob
Node como tudo o que já lá está.

**4. A infra de formulário NÃO se move.** `makeWizard`, `makePicker`,
`createCombo` e vizinhas — 514 linhas com 13 sinks — são a situação do modal
de log multiplicada por três: mover tal-e-qual introduz sinks em `ui/`;
reescrever como DOM é reimplementar widgets com estado, foco e teclado, cada
um com o seu risco próprio. Ficam em `bin/dashboard.html`, dito no commit com
a razão, registado aqui como trabalho com nome. A lista de conversões
pendentes passa a ser: o modal de log, e estes três widgets.

## Riscos conhecidos

**Os editores gravam dados.** As fases 1 e 2 moviam superfícies de leitura;
aqui um erro no `readForm` corrompe um job. Por isso a ordem é pinar →
restilizar → mover o puro, e o restyle não toca no `readForm`.

**O modo wizard tem validação por passo e o modo tabs não valida da mesma
forma.** O restyle tem de preservar os dois caminhos — o teste do modo duplo
existe para isso.

**O seletor de modelo/esforço do painel Security do projeto é o mesmo do
job** — exigência antiga do utilizador, pinada por
`test_security_model_and_effort_use_the_job_editors_controls`. O restyle não
pode fazê-los divergir.

## Decisões que este documento toma sozinho

1. **A infra de formulário fica** (ponto 4 acima) — precedente do modal de log.
2. **O markup dos dialogs restiliza-se no sítio** em vez de se mover — mover
   markup estático não compra nada e a regra de sinks não o pede.
3. **`editor-domain.js` recebe só o puro** — o critério é «testável sob Node
   sem stub de DOM».

## Fora de âmbito

O índice Security (Fase 4). A conversão a DOM do modal de log e dos três
widgets de formulário (trabalho nomeado, sem fase atribuída).

## Verificação

Os portões habituais: `pytest`, `claude-cron selftest`, `test/e2e.test.sh`,
árvore limpa, artefactos no mesmo commit. E o teste do contrato de render
verde desde a primeira tarefa.


## Correcções pós-implementação

**O pino «formulário intocado não avisa» era mais fraco do que a spec
alegava.** O teste cobre a comparação (`changedKeys`), mas ao vivo um editor
de job acabado de abrir lia-se como sujo durante o fetch do precheck — o
snapshot limpo era tirado antes do placeholder «loading…» entrar no campo.
Pré-existente (o bloco era byte-idêntico através da fase), encontrado pela
revisão final ao tentar o caminho que o teste não vê. Corrigido no fecho:
o placeholder entra antes do snapshot.

**Dois fieldhelps encurtados perderam o essencial, não só o comprimento** —
o do base branch deixou de avisar do checkout detached/stray que todos os
runs herdam, e o do config dir perdeu o termo pesquisável
`CLAUDE_CONFIG_DIR`. Repostos no fecho, encurtados mas com o perigo. A regra
(«o texto pode encolher, o significado não») manteve-se válida; a aplicação
falhou em 2 dos 14 casos e a revisão apanhou-os.

**A navegação numerada existe nos dois modos** — a distinção editar/criar é
comportamental (tudo alcançável + marcas de edição, vs. avanço validado +
vistos), não visual. Um comentário antigo prometia «plain tab strip when
editing»; corrigido, junto com duas frases do CHANGELOG que herdaram o
«flat».

**O scan do contrato de render tinha uma chamada directa fora da lista**
(`worktreesCard`), inerte hoje mas contrária ao que a docstring alegava;
acrescentada, e um teste novo obriga cada `<dialog>` da página a estar
arquivado numa das duas listas — guardado ou deliberadamente vivo.
