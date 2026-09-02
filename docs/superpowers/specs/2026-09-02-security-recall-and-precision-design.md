# Bloco 3 — recall, assertividade e um relatório legível — design

> **Origem:** depois da primeira análise real com os motores (Minerva, `develop`,
> 2026-09-02), o operador descreveu o resultado como *"RR muito baixo e
> assertividade mediana"*. Este documento regista o que foi **medido** antes de
> desenhar, porque o diagnóstico inicial estava errado em dois terços.

**Objectivo:** que uma análise encontre o que existe, não grite sobre o que não
importa, e que quem a lê perceba em dez segundos o que foi e não foi verificado.

---

## O que foi medido, por ordem de descoberta

### Primeira leitura: perdemos 91% dos segredos

| | Análise 8 (scanner interno) | Análise 9 (Gitleaks) |
|---|---|---|
| `secret` | 23 | **2** |
| `low` + `info` | — | **69% dos achados** |

Foi esta a leitura que motivou o pedido. Está correcta nos números e errada na
conclusão.

### Segunda leitura: o que eram os 21 que desapareceram

Medido no checkout do Minerva, com os filtros de produto aplicados a ambos os
scanners:

| | scanner interno | Gitleaks |
|---|---|---|
| ficheiros com achados | 24 | 2 |
| só este vê | 22 | **0** |

O Gitleaks é um **subconjunto estrito** do interno neste repositório. Mas os 22
ficheiros "perdidos" decompõem-se assim:

- **3 `private_key` — todos só-cabeçalho**, em testes adversariais, num harness
  de conformidade e em planos de documentação. Nenhum tem corpo PEM. O Gitleaks
  exige o corpo; o interno não. **Falsos positivos do interno.**
- **1 `aws_access_key` — é `AKIAIOSFODNN7EXAMPLE`**, a chave de documentação da
  AWS, num plano. O Gitleaks tem-na em *allowlist*. **Falso positivo do interno.**
- **22 ocorrências de `generic_secret` em `.superpowers/`**, que está
  **git-ignored**. O interno tem `SKIP_DIRS` mas `.superpowers` não está lá — é o
  mesmo defeito de âmbito que corrigimos no Gitleaks no bloco 2, e nunca ninguém
  o verificou no scanner que o Gitleaks veio substituir. **Ruído de âmbito.**
- **9 em `docs/`** — exemplos em documentação.
- **15 `generic_secret` em código real**, e aqui está o único recall
  genuíno em causa. Caracterizados sem ler valores: tokens de 48 caracteres,
  entropia 3,8–4,1. **O mesmo token aparece repetido em `scripts/seed-auth.py`,
  `services/knowledge-api/tests/_auth.py` e na colecção Postman** — são tokens
  de *seed* para testes, partilhados entre o script que os cria, os testes que os
  usam e a colecção que os exercita. Mais dois `.env` **git-ignored**, portanto
  locais do operador e não do repositório.

**Conclusão corrigida:** a "perda de 91%" era em cerca de 85% ruído a
desaparecer. O recall real perdido são tokens de teste que o Gitleaks descarta
por entropia — e não é óbvio que descartá-los seja errado.

**Errata (Task 2, medido no Minerva):** a segunda medição, feita ao implementar
a união com o binário e com o âmbito da Task 1 aplicado aos dois scanners,
encontrou **cinco** `private_key` do interno, não três: dois só-cabeçalho
(`clients/minerva-connect/test/adversarial.test.js` e
`clients/minerva-connect/test/conformance/_harness.js`, ambos código de teste)
e **três com corpo** (`clients/minerva-connect/test/redact.test.js` e o plano
rp144, com uma linha base64 a seguir ao cabeçalho; o plano rp154, com um PEM
inteiro numa só linha com `\n` escapados). O Gitleaks assinala `redact.test.js`
e rp144 quando o seu passe de árvore corre. A conclusão de desenho mantém-se:
o padrão `private_key` do interno passa a exigir corpo, os dois só-cabeçalho
deixam de ser achados e os três com corpo ficam — são achados legítimos ou
exemplos com forma de chave em documentação, matéria de triagem, não de padrão.
Também o motivo do descarte dos tokens de seed foi medido: o Gitleaks
descarta-os pela **forma snake_case** (palavras minúsculas unidas por `_`, com
dígitos no fim), não pela entropia — as mesmas letras sem `_` são assinaladas.
Uma medição posterior (gitleaks 8.30.1, 20 valores) mostrou que a causa é a
**lista de stopwords** da regra genérica (1 446 entradas, muitas com separador
final — `our_` e `con_` são entradas), não a forma: a mesma forma snake_case
sem stopword é assinalada, um valor antes assinalado passa a descartado quando
se lhe insere `our_`, e a sonda de retirar os `_` não discriminava porque
retirava também o `our_`; a entropia nunca foi o motivo (4,26 na fixture,
3,8–4,1 nos tokens de seed, todos acima do limiar 3,5 da regra).

### Terceira leitura: porque é que 69% é `low`/`info`

A spec original assenta num argumento: *o ruído não é filtrado por heurística,
é o agente que lê o código à volta e tria*. É o Job 2 da skill. **Medido na
análise 10: o Job 2 não aconteceu.**

| | |
|---|---|
| Achados determinísticos gravados por `prepare` | 40 |
| Achados determinísticos re-reportados pelo agente com severidade corrigida | **0** |
| Subagentes lançados pelo agente | **6**, todos para o Job 3 (SAST por área) |
| Chamadas a `report-finding` no log principal | 0 — foram os subagentes que reportaram |
| Custo da análise 9 (perfil `deep`) | **$51,44** |

O agente gastou o orçamento inteiro no SAST próprio, dividido por seis
subagentes, e não triou um único achado dos motores. Os 40 ficaram com a
severidade que o padrão lhes deu. **A assertividade mediana não é um defeito dos
motores; é a triagem que a spec prometeu e que não se materializa.**

Nada o obriga: `cmd_finish --state done` não verifica que a triagem aconteceu,
e nem a skill nem o prompt da análise mencionam subagentes — a decisão *"um
agente, não subagentes"* da spec original nunca chegou a quem a devia cumprir.

### Quarta leitura: o relatório que ninguém lê

O `coverage_note` da análise 10 tem cerca de 2.000 caracteres. É montado por
concatenação de **27 constantes** (`*_NOTE`) espalhadas por seis módulos, cada
uma acrescentada por uma tarefa do bloco 2 para ser honesta sobre uma lacuna.
Cada frase é verdadeira. O conjunto levou o operador a perguntar *"o que é este
alerta?"* — e se quem construiu o sistema não o lê, ninguém lê. Um revisor
tinha avisado: *"honesto por frase, incoerente como um todo"*. Tratámos as
frases.

---

## Decisões

| Decisão | Porquê |
|---|---|
| **Validação viva de credenciais fica fora** | decisão do operador, 2026-09-02: mantém-se a regra da spec original — nenhum segredo sai da máquina. |
| **O scanner interno ganha o âmbito que o Gitleaks já tem** | é um defeito, não uma escolha. `.superpowers/` git-ignored a produzir 22 achados é o mesmo bug corrigido no bloco 2, no motor que ficou por ver. |
| **União de motores de segredos, com dedup por fingerprint** | o Gitleaks e o interno vêem conjuntos diferentes. A regra "um motor por categoria" foi tomada para evitar identidades duplicadas; o fingerprint de segredo é `tipo + caminho` e o `RULE_RENAMES` já mapeia os tipos — a dedup existe. Mas a união só entra **depois** do âmbito estar corrigido, senão traz de volta o ruído. |
| **A triagem passa a ser verificável, não pedida** | uma instrução que o agente pode ignorar sem consequência é o que aconteceu. `finish --state done` exige que os achados determinísticos acima de um limiar tenham sido lidos pelo agente; sem isso fecha como `capped` e diz porquê. |
| **Subagentes: proibidos por defeito, com o custo como razão** | a spec original decidiu-o e não o escreveu onde contava. Seis subagentes num perfil `deep` custam $51 por análise. A skill e o prompt passam a dizê-lo, e o `finish` regista quantos foram lançados. |
| **O `coverage_note` deixa de ser prosa** | passa a ter estrutura — o que correu, o que não correu, avisos — com cada fase numa linha. A prosa longa fica disponível mas dobrada, para quem quiser o porquê. |

---

## Âmbito

**Entra:**

1. **Âmbito do scanner interno** — `.superpowers` e o que o Gitleaks já
   exclui entram em `SKIP_DIRS`; o filtro de sufixo de template aplica-se
   igual nos dois. Medir antes e depois no Minerva.
2. **União de segredos** — correr Gitleaks **e** interno quando ambos existem,
   unir por fingerprint (o `RULE_RENAMES` do bloco 2 é o mapa de tipos), gravar
   `producer` como a lista dos que viram. O `coverage_note` diz quantos só um
   viu.
3. **Triagem verificável** — `finish --state done` recusa se houver achados
   determinísticos com severidade ≥ `medium` que o agente não re-reportou; a
   skill reordena os três jobs para que a triagem venha **antes** do SAST e
   receba orçamento primeiro. A alcançabilidade de dependências é parte desta
   triagem (a skill já a pede: *"is this CVE on a code path anything reaches?"*).
4. **Controlo de subagentes** — proibição explícita na skill e no prompt;
   contagem registada na análise; `capped` se exceder zero sem justificação.
5. **`coverage_note` estruturado** — um formato por fase (`ran` / `did not
   run` / `warning`), render compacto no relatório e na UI, prosa dobrada.

**Fica de fora:** validação viva (decisão do operador); rever a severidade que
cada motor atribui (é o que a triagem faz caso a caso, e generalizar sem dados é
adivinhar).

---

## Falhas e limites

- **A união traz falsos positivos do interno se o âmbito não estiver
  corrigido.** Por isso o item 1 precede o 2, e a medição antes/depois é o
  critério de aceitação: o número de ficheiros com achados só do interno tem de
  cair para perto de zero *fora de código de teste* antes de a união entrar.
- **A triagem verificável pode fazer análises fechar `capped`** que hoje fecham
  `done`. É o comportamento pretendido: uma análise que não triou não está
  completa, e dizê-lo é melhor do que fingir. Mas o limiar (`medium`) tem de ser
  medido — se metade das análises ficar `capped`, o limiar está errado.
- **Sem subagentes, o perfil `deep` num repositório grande pode não caber no
  orçamento.** Também é o pretendido: o `capped` diz o que ficou por ver, e o
  operador escolhe entre mais orçamento e um perfil mais estreito. Fingir
  cobertura com seis agentes a $51 não é uma alternativa.
- **O `coverage_note` estruturado muda o formato de um campo que a UI e os três
  relatórios já lêem.** O texto plano continua a existir para compatibilidade;
  a estrutura vive ao lado.

---

## Riscos

1. **O limiar da triagem.** `medium` é um palpite informado. A primeira análise
   depois deste bloco diz se está certo.
2. **A união pode duplicar onde o `RULE_RENAMES` não mapeia** — `github_token` e
   `slack_token` ficaram deliberadamente sem mapa no bloco 2 porque uma regra
   nossa corresponde a quatro deles. Esses aparecem duas vezes até haver mapa; o
   `coverage_note` tem de o dizer.
3. **Custo.** A análise 9 custou $51. Este bloco reduz-o por duas vias —
   sem subagentes, e com a triagem a receber orçamento antes do SAST — mas não o
   mediu ainda. A primeira análise depois do bloco mede.
