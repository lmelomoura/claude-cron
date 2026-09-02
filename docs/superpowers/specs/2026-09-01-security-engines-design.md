# Bloco 2 — os quatro motores — design

> **Origem:** o bloco A1 de `2026-09-01-security-parity-and-differentiation.md`.
> Este documento substitui as suposições dessa lista pelo que foi **medido em
> 2026-09-01** neste repositório, com os quatro motores instalados. O bloco 1
> (taxonomia e identidade) está em `main` desde o PR #19.

**Objectivo:** substituir a detecção artesanal por motores maduros, mantendo a
arquitectura — Python escreve no ledger, o agente nunca escreve — e usando o
agente onde ele é insubstituível: a triagem contextual do que os motores
produzem.

---

## O que a medição mostrou

Sobre este repositório (120 ficheiros versionados, ~56k linhas de Python,
JavaScript e shell, 418 commits):

| Motor | Versão | Tempo | Resultado |
|---|---|---|---|
| **Semgrep** `p/owasp-top-ten` | 1.175.0 | **6,0 s** | 223 regras, 85 ficheiros, 99,9% das linhas, **3 achados** |
| **Gitleaks** `dir` (árvore) | 8.30.1 | **2,2 s** | 24,7 MB varridos, **17 achados** |
| **Gitleaks** `git` (histórico) | 8.30.1 | **1,6 s** | 396 commits, **2 achados** |
| **Trivy** `fs` (vuln+secret+misconfig) | 0.74.0 | **9,4 s** | **6 vulnerabilidades**, 0 segredos, 0 misconfig |
| **Syft** (CycloneDX) | — | **1,8 s** | **7 componentes** |

**Total: ~21 segundos.** O risco "a fase determinística deixa de ser segundos"
não se materializa a esta escala. Extrapolando linearmente para um monorepo cem
vezes maior dá cerca de trinta minutos, o que já é outro produto — mas é um
problema a resolver quando existir, não agora.

### As cinco coisas que a medição desmentiu ou revelou

1. **Os ficheiros sem extensão são analisados.** `bin/claude-cron` (8.263
   linhas) e `bin/claude-cron-server` (3.473) entram os dois: o Semgrep escolhe
   o analisador pelo shebang. A preocupação era infundada.

2. **A cobertura de shell é residual: 1 regra, contra 147 para Python e 65 para
   JavaScript.** O núcleo deste produto é bash. **O Semgrep não substitui o SAST
   do agente — complementa-o**, e num projecto cuja lógica viva em shell
   acrescenta quase nada. Isto contradiz a formulação do bloco A1, que o
   descrevia como "o maior salto de cobertura": é o maior salto **para projectos
   Python/JS/Go**, e quase nenhum para shell. O `coverage_note` tem de o dizer,
   por linguagem.

3. **Os 3 achados do Semgrep são 3 falsos positivos, e do tipo que só o contexto
   resolve.** Todos `insecure-hash-algorithm-md5` (CWE-327), todos em usos
   não-criptográficos: chaves de cache, ETags, um comentário que diz
   literalmente *"cheap fingerprint of the file head"*. O filtro de ruído do
   GitGuard não os apanharia — não são ficheiros de teste nem dependências de
   desenvolvimento. É a validação empírica do argumento central da spec-mãe.

4. **O Gitleaks varre o *filesystem*, não o versionado.** Dos 17 achados na
   árvore, quinze estão em `.superpowers/` (git-ignorado), `__pycache__/` e
   `data/logs/`. O nosso `secrets.py` tem `_SKIP_DIRS` e obedece a
   `ignore_paths`; o Gitleaks não sabe nada disso. Sem configuração explícita, a
   troca de motor **aumenta** o ruído em vez de o reduzir.

5. **O Trivy só encontrou o que estava nas nossas próprias fixtures de teste.**
   As 6 vulnerabilidades estão em `tests/security/fixtures/package-lock.json` e
   `poetry.lock`. O `package.json` da raiz não produziu nada — sem lockfile, não
   há SCA. E 0 misconfigurações, porque não há Dockerfile, Terraform nem
   manifestos K8s neste repositório: o item IaC não é testável aqui e precisa de
   um repositório que o exercite.

---

## O problema do valor em claro, e o que o log revelou

O JSON do Gitleaks traz **dois** campos com a credencial em claro — confirmado
por inspecção do output real, não pela documentação:

```
RuleID, Description, StartLine, EndLine, StartColumn, EndColumn,
Match  ← o valor, em claro
Secret ← o valor, em claro
File, SymlinkFile, Commit, Entropy, Author, Email, Date, Message,
Tags, Fingerprint
```

Isto já estava previsto. **O que não estava previsto foi encontrado nos logs
deste repositório**, e é o achado mais importante desta medição.

O ficheiro `data/logs/security-minerva/20260821T063112Z-61093.stream.ndjson`
contém um bloco PEM completo de 1.546 caracteres, gravado como `stdout` de uma
ferramenta que o agente de segurança correu. O comando que o produziu foi escrito
pelo próprio agente, e ele **tentou** proteger-se:

```bash
mask() { sed -E 's/[A-Za-z0-9_\-\/\+=]{16,}/<REDACTED>/g'; }
echo "=== redact.test.js:1-30 ==="; sed -n '1,30p' clients/…/test/redact…
```

A função de mascaramento foi definida e **nunca ligada ao pipe**. A defesa foi
construída e não foi usada, e nada o assinalou.

O ficheiro em causa parece ser uma fixture de teste de redacção, portanto o risco
concreto é baixo. **O mecanismo não é.** A promessa "nenhum valor de segredo
chega ao ledger, a um report ou a um log" dependia de o agente se lembrar de
aplicar um `|`, e não se lembrou. A skill diz-lhe para nunca imprimir um valor;
não impede que uma *ferramenta que ele corre* o imprima.

**Consequência para este bloco:** a protecção tem de deixar de ser uma instrução
e passar a ser estrutural. Duas exigências que daqui saem:

- **O adaptador do Gitleaks descarta `Match` e `Secret` à entrada**, antes de
  qualquer coisa — ledger, log, stdout — os poder ver. O motor corre com output
  para ficheiro, nunca para um stream que o log capture.
- **O teste adversarial que já existe passa a cobrir o caminho dos motores**, e
  a asserção alarga-se: a string injectada não pode aparecer no ledger, em
  nenhum dos três formatos de report, **nem no `.stream.ndjson` da run**.

---

## Decisões

| Decisão | Porquê |
|---|---|
| **Binários opcionais, detectados em runtime** | decidido com o âmbito. A medição reforça-o: nenhum dos quatro estava instalado nesta máquina, portanto a degradação declarada é o caminho normal, não a excepção. |
| **Um motor por categoria** | o Trivy também detecta segredos (correu com `--scanners secret` e devolveu 0). Deixar dois motores na mesma categoria produz o mesmo achado com dois fingerprints. O Gitleaks fica com `secret`, o Trivy com `dependency` e `iac`, o Syft com o SBOM, o Semgrep com `sast`. |
| **O Gitleaks corre com a nossa configuração de âmbito** | sem isso varre `.superpowers/`, `__pycache__` e `data/logs/`. Os `_SKIP_DIRS` e os `ignore_paths` do projecto têm de chegar-lhe como configuração, senão a troca de motor piora o ruído. |
| **O `coverage_note` passa a declarar cobertura por linguagem** | "o Semgrep correu" é verdade e é enganador num repositório de shell. O que o relatório tem de dizer é quantas regras correram para cada linguagem presente. |
| **O Semgrep não substitui o SAST do agente** | 1 regra para shell. O agente continua a ser o SAST primário; o Semgrep é uma pré-passagem cujo output ele tria. |

---

## Âmbito

**Entra:** o adaptador comum com detecção de binário e degradação declarada; os
quatro motores; a nova categoria `iac`; o campo `scope` (dev/runtime) nas
dependências; `fixed_version` nos CVEs; e a supressão por omissão de
testes/fixtures e de `.example`/`.sample`/`.template` no scan de segredos.

**Fica de fora:** licenças (item A2.10 — trivial de acrescentar depois de o
adaptador do Trivy existir, e não vale atrasar este bloco); e tudo o que a
spec-mãe já pôs nos blocos 3 a 5.

**O `scope` (dev/runtime) foi implementado depois do resto do bloco, e a lista
*Entra* está completa.** A coluna `scope` existe no ledger (`runtime`, `dev`,
`unknown`, ou vazio num achado que não é de dependência), é escrita pelos dois
produtores da categoria `dependency`, e aparece nos três formatos de relatório
e nas linhas que o ecrã lê.

**Três valores, não dois, e o terceiro é a decisão de desenho.** "Não está
marcado como dev" não é o mesmo facto que "runtime": três dos cinco formatos de
lockfile não conseguem exprimir a distinção. Responder `runtime` aí exagerava a
confiança de tudo; responder `dev` escondia risco real. `unknown` é a única
leitura honesta de um ficheiro que não carrega o facto — e é o que sai sempre
que um produtor olhou e o formato não soube responder.

**Os dois produtores concordam, e isso foi medido, não assumido.** Só um deles
corre por análise (`cli._scan_dependencies`) e qual deles depende de a máquina
ter o Trivy — portanto duas leituras diferentes da mesma regra dariam à mesma
vulnerabilidade um `scope` diferente conforme o binário instalado, que é o erro
que este bloco já pagou três vezes. A regra vive numa função só
(`deps.merge_scope`), chamada pelos dois. A paridade foi corrida ao vivo sobre
árvores reais com uma dependência de desenvolvimento vulnerável e uma de
produção vulnerável, em npm, composer e poetry (lock-version 1.1 e 2.1): os dois
produtores devolvem os mesmos identificadores de aviso e o mesmo `scope`. O
teste está em `tests/security/test_adapters.py`.

**A única divergência conhecida está declarada em nota de cobertura, não
escondida:** num `poetry.lock` de lock-version 2.0 (Poetry 1.5 a 2.0) não há
nem `category` nem `groups` — a pertença ao grupo só existe no
`pyproject.toml`, que o Trivy lê e propaga pelo grafo resolvido e que o leitor
manual deste projecto não tem como ler. Aí o Trivy responde `dev` e o inventário
responde `unknown`. A diferença é sempre nesse sentido: o nosso leitor nunca
afirma `runtime` onde o Trivy diria `dev`.

**O `--include-dev-deps` passou a ser passado ao Trivy, e não é um detalhe do
`scope`.** Medido: sem essa flag o Trivy não põe a dependência de
desenvolvimento no relatório de todo. O `deps.inventory` sempre as leu, portanto
o mesmo repositório reportava menos achados numa máquina com Trivy do que numa
sem — a mesma divergência por máquina. Um CVE só-de-dev não é ruído a descartar;
é um achado a ordenar, que é para isso que o `scope` serve.

---

## Falhas e limites

- **Motor ausente** — a análise corre com o que existir e declara a lacuna, pela
  mesma regra que já governa a OSV sem rede.
- **Motor presente com versão incompatível** — trata-se como ausente, e o
  `coverage_note` diz que versão foi encontrada e qual é exigida. Um parser que
  assume um formato que mudou é pior do que um motor que não correu.
- **Fidelidade das fixtures** — o output de cada motor tem de ser **capturado a
  correr a ferramenta**. As capturas desta medição estão no scratchpad da sessão
  e devem ser commitadas como fixtures, depois de purgadas de qualquer valor.
- **Migração de identidades** — o `migrate-rules` do bloco 1 existe para isto.
  As regras de segredos mudam todas de nome (`aws_access_key` →
  `aws-access-token`, e por aí). É a primeira utilização real de
  `taxonomy.RULE_RENAMES`, e é a que valida o mecanismo.

---

## Riscos

1. **O ruído do Gitleaks se a configuração de âmbito falhar.** Medido: 17
   achados, 15 dos quais fora de código versionado. É o risco mais provável
   deste bloco e o mais fácil de detectar cedo.
2. **A cobertura de shell continuar a ser residual.** Não é um risco que
   possamos mitigar — é uma propriedade do ecossistema Semgrep. Mitiga-se
   dizendo a verdade no relatório.
3. **O volume de triagem num repositório grande.** Aqui foram 3 achados de
   Semgrep e 6 de Trivy, o que torna a triagem trivialmente barata. Um
   repositório com centenas muda essa conta, e é aí que o `min_severity` e o
   `ignore_paths` deixam de ser conveniências e passam a ser controlo de custo.
