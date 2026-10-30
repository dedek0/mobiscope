# Roadmap

**Status:** documento vivo · atualizado em 2026-10-30
**English:** [roadmap.md](roadmap.md)

Este arquivo registra o que foi feito, o que vem a seguir e as decisões por
trás de cada passo. Use junto com
[docs/analyzers.md](analyzers.md) (referência por estágio) e
[docs/artifacts.md](artifacts.md) (schema dos artefatos).

## Princípios

1. **Sinal antes de volume.** Finding que dispara em toda biblioteca de
   terceiros é ruído. Agregue ou remova.
2. **Não depender de um decompilador para fatos básicos.** Manifest,
   resources, strings dos DEX e material de assinatura podem ser lidos direto
   do APK.
3. **Todo backend novo é opcional e fail-soft.** Ferramenta ausente degrada o
   relatório, nunca quebra o pipeline.
4. **Findings continuam determinísticos.** Os IDs derivam de ferramenta,
   categoria, arquivo, linha e snippet (ADR-002). Mudanças de backend que
   alterem localização exigem decisão explícita de compatibilidade.
5. **Documente a decisão, não só a tarefa.** Escolhas arquiteturais ganham um
   ADR em [docs/adr/](adr/).

## Estado atual (Android)

O run padrão (`mobiscope analyze app.apk`) executa `apktool`, `jadx`,
`apksigner`, `elf`, `anti-analysis`, `repack`, `sdk` e `inventory`.
`gitleaks` e `semgrep` são opt-in via `--stages`.

Pontos fortes:

- Hardening de ELF e anti-analysis in-process, direto do APK.
- Manifest decodificado com `encoding/xml` e NSC resolvido pelo manifest.
- Findings determinísticos, dedup/clustering, SARIF e Markdown.
- Triage por LLM provider-agnostic com gate local para secrets.

As lacunas estão agrupadas abaixo. P0–P3 estão implementados; a avaliação do
backend de decompilação é o trabalho planejado restante.

## P0 — qualidade do sinal (feito)

Estas mudanças removeram o ruído que tornava ilegível um relatório real
(TP-Link IoT, 47 mil entradas ZIP, 18 DEX): 1.597 findings, sendo 1.080 de
pinning, 424 de IP e 43 de e-mail.

### Findings e agregação

- **Pinning é propriedade do app.** O `inventory` emite um único finding
  informativo listando os marcadores (`X509TrustManager`, `CertificatePinner`,
  `TrustKit`, `sha256/`, `pin-sha256`, `BEGIN CERTIFICATE`). O agregado fica
  em `inventory.json` (`pinning_indicators`, `pinning_count`).
- **IPs e e-mails são inventário, não findings.** `ip_count`/`ips` e
  `email_count`/`emails` são amostras limitadas e ordenadas.
- **Platform sempre preenchida.** Todo finding do `inventory` agora carrega
  `platform: android`.
- **Private key exige bloco PEM completo.** Constantes que só têm o header
  (JSch, Netty e afins) não geram mais falso positivo crítico. O bloco precisa
  ter corpo base64 válido, e o corpo é redigido de evidências, relatórios e
  prompts do LLM.
- **Chaves client-side são informativas.** GCP API key, OAuth client ID e URL
  do Firebase são identificadores, não segredos de servidor; saem como `info`
  com explicação.
- **Repack recalibrado.** Multidex, assinatura só v2/v3 e timestamp
  normalizado são normais e não geram mais finding. O estágio reporta
  payloads executáveis em `assets/` (high) e bibliotecas nativas em `assets/`
  (low).
- **Findings de repack e SDK realmente emitidos.** `Repack` e `SDK` agora
  implementam `ConvertFindings`, então a asserção `FindingConverter` do
  pipeline chega neles.
- **Falsos positivos de anti-analysis removidos.** O estágio não varre mais
  assets de dados (metadata do Unity e afins); só DEX e assets executáveis.
  As needles soltas `su`/`gadget` saíram, então palavras comuns não disparam
  mais root/Frida.
- **`--stages` normaliza hífen/underscore.** `anti-analysis` e `anti_analysis`
  agora selecionam o mesmo analyzer; antes a forma documentada com hífen não
  casava com nada.
- **Relatório mostra representantes de cluster.** O `report.md` renderiza o
  representante de cada cluster + “N ocorrências”; `findings.json` e
  `report.sarif` mantêm todas.

### Assinatura

- Findings do `apksigner` estão ligados ao pipeline (debug-signed, sem
  assinante, só v1).
- Quando o `apksigner` não existe (a imagem Docker não o traz), o fallback
  agora detecta o **APK Signing Block** (v2/v3) em vez de assumir que a
  ausência de `META-INF/*.RSA` significa “sem assinatura”. Isso remove um
  falso crítico em APKs modernos.

### Pack semgrep

O pack Android agora valida no `semgrep 1.127.1`
(`semgrep --validate --config internal/rules/mastg/rules.yaml`). Correções:

- `mastg-trustmanager-bypass` só casa trust check vazio, não toda
  implementação de `checkServerTrusted`.
- `mastg-crypto-hardcoded-key` só casa chave literal.
- `mastg-storage-world-accessible` só casa `MODE_WORLD_*`.
- `mastg-crypto-no-padding` casa transformações `".../NoPadding"`.
- `mastg-webview-ssl-error` só inspeciona handlers `onReceivedSslError`.
- `mastg-webview-file-access` usa severidade válida do semgrep.
- `mastg-exported-component` é limitado a `AndroidManifest.xml`.
- `mastg-crypto-pbe-weak` tinha padrão inválido (`$PBEKeySpec(...)`) que
  tornava o pack inteiro inutilizável; agora usa `new PBEKeySpec(...)`.

### Inventário

- `obfuscation` é preenchido pelo estágio `anti-analysis` (ratio, número de
  classes, toolchain).
- `network.kind` só é preenchido quando existe network security config;
  `cleartext_permitted` e `pinned` vêm dela.

## P1 — análise Android nativa (feito)

Objetivo: tornar os checks principais independentes de `apktool`/`jadx` e
rápidos o suficiente para CI. O estágio `inventory` agora lê o APK in-process
e só cai para a árvore decompilada quando o parse nativo falha. Veja o
[ADR-010](adr/010-native-apk-parsing.md).

1. **Parser de AXML e `resources.arsc` em Go.** (feito)
   `axml.go` decodifica XML binário compilado (string pool, resource map,
   valores tipados, namespaces, CDATA); `arsc.go` lê a tabela de resources
   para resolver `@xml/…` / `@string/…` sem apktool. O `inventory` lê
   `AndroidManifest.xml` e o network security config direto do APK, então
   manifest/permissões/NSC sobrevivem a OOM do decompilador e
   `--stages inventory` funciona em sessão nova (`--quick` ganha sentido).
2. **Scanner da string table dos DEX.** (feito)
   Cada `classes*.dex` tem a string pool varrida por secrets, URLs, IPs,
   e-mails, pinning e os mesmos padrões de código da árvore. Hits de DEX são
   deduplicados contra a árvore por categoria + evidência, e agregados DEX só
   entram quando a árvore não produziu nenhum. Fecha a lacuna de `semgrep`
   ser opt-in e só ver `.java`.
3. **Parse completo do network security config.** (feito)
   `nsc.go` lê `cleartextTrafficPermitted` base e por domínio,
   `debug-overrides`, `overridePins`, `pin-set`/`expiration` e trust anchors.
   Só relaxamentos reais viram finding; o resultado estruturado preenche
   `inventory.network.exceptions`.
4. **Checks de manifest targetSdk-aware.** (feito; assetlinks adiado)
   - Defaults de `android:exported`/provider dependem de `targetSdk` e do
     tipo; atributo ausente em targetSdk ≥ 31 não é reportado como exportado
     (a plataforma rejeita esse manifest).
   - App Links: filtro VIEW `https` browsable sem `autoVerify` é reportado.
     Buscar `assetlinks.json` fica para um estágio de rede (`--osv` continua
     sendo o único egress).
   - Task hijacking combina `taskAffinity`, `launchMode` e
     `allowTaskReparenting`.
   - Default de `usesCleartextTraffic` por `targetSdk`; filhos
     `<grant-uri-permission>`; defaults de provider.
   - `dataExtractionRules`/`fullBackupContent` são expostos; sinalizar
     diretórios sensíveis a partir do arquivo de regras fica para o P2.
5. **Origem do finding.** (feito)
   `Finding.origin` é `app` ou `sdk:<nome>`, derivado dos prefixos de classe
   do estágio `sdk` mapeados nos caminhos decompilados. O pipeline preenche o
   campo para findings de semgrep/gitleaks, então “OkHttp menciona
   X509TrustManager” e “o app desativa validação de TLS” ficam distinguíveis.

## P2 — cobertura (feito)

- **Kotlin e taint.** (feito) O pack ganhou regras Kotlin (segredos
  hardcoded, `addJavascriptInterface`, log sensível, cifras fracas,
  concatenação em SQL) e regras em modo taint para intent/deeplink → WebView,
  SQL, arquivo e exec, clipboard → log e intent redirection. Também cobre
  `ContentProvider.openFile` traversal e PendingIntent mutável (a regra
  genérica foi endurecida para exigir `FLAG_IMMUTABLE` ausente). O build
  Docker agora valida os dois packs com `semgrep --validate`.
- **Profundidade nativa.** (feito) `RegisterNatives` é sinalizado; `.so` em
  `assets/` é inspecionado; `DT_SONAME`, entropia de Shannon e assinaturas de
  packers (UPX, 360 Jiagu, Tencent Legu, Alibaba, Bangcle, …) entram em
  `native_libs`, com findings de `obfuscation` para alta entropia e packing.
- **Detecção de SDK.** (feito) As assinaturas cobrem Huawei HMS, WeChat,
  Bugly, MMKV, Alipay, Umeng, JPush, Baidu, Play Billing, Flutter, Unity,
  Apache HttpClient, Bouncy Castle, SQLCipher, ZXing e a stdlib Kotlin, além
  do conjunto Firebase/OkHttp/Gson. Versões vêm de
  `META-INF/maven/*/pom.properties`, string resources decodificados e classes
  `BuildConfig`; SDKs native-only são detectados pelo nome do `.so`.
- **Assinatura em Go.** (feito) O APK Signing Block v2/v3/v3.1 é lido e
  verificado criptograficamente in-process: assinatura sobre o signed data,
  digest de conteúdo em chunks (SHA-256/SHA-512), scheme, número de signers,
  fingerprint SHA-256, subject, validade, algoritmo/tamanho de chave, presença
  de v1 e detecção de debug. Um artefato adulterado vira
  `digest-mismatch`/`invalid-signature`. Lineage de rotação e presença de
  source stamp são detectados.
- **Estágio de obfuscação.** (feito no escopo P2) O estágio `anti-analysis`
  detecta artefatos R8/ProGuard/DexGuard, nomes curtos de classe e toolchain
  de obfuscação, e `analyze --mapping mapping.txt` reescreve caminhos e nomes
  de classe obfuscados nos findings antes de baseline/triage. Reflection e
  decodificação Base64 em runtime são sinalizados pelo `anti-analysis` e pelo
  semgrep (`mastg-reflection`, `mastg-string-encryption`).
- **Diff, baseline e gate de CI.** (feito) `mobiscope diff old.apk new.apk`
  com `--json`, `analyze --baseline <findings.json|session.json>` e
  `analyze --fail-on <severity>` (exit code 2). O casamento é por fingerprint
  e independente de número de linha. Uma allowlist embutida ignora
  componentes de infraestrutura AndroidX/bibliotecas, e
  `--allowlist allowlist.yaml` aceita regras extensíveis (cada uma com
  `reason` obrigatório) para identificadores públicos conhecidos.
- **Validar nomes de estágio.** (feito) Um `--stages` inválido agora falha
  listando os nomes válidos para a plataforma detectada.

## P3 — performance e relatório (feito)

- Parar de rodar os dois decompiladores completos por padrão. (feito) O padrão
  agora é só `jadx`; o parser nativo de AXML/arsc cobre manifest/resources/NSC,
  e o `apktool` só roda quando nomeado ou com `--decompiler`.
- Cachear saída de decompilador por SHA do APK e oferecer `--reuse`. (feito)
  A sessão já é keyed pelo SHA; `--reuse` pula o decompilador cuja árvore
  existe.
- `scanPatterns`: (feito) as regras têm um prefilter `Needle` barato antes do
  regex; árvores de SDK vendor são puladas (o scanner DEX cobre as strings) e
  os arquivos são processados por um pool de workers limitado.
- Relatório: (feito) representantes + contagens, top clusters/categorias e uma
  seção de superfície (pacote/versão/targetSdk, permissões, SDKs, ABIs
  nativas, política de rede, assinatura). Listas de componentes/deeplinks
  ainda vêm dos findings, não de uma tabela de superfície dedicada.
- Triage: (feito) só representantes com severidade ≥ `low` são enviados;
  findings info são fatos de inventário/superfície e não gastam LLM.
- Fixtures golden com os traps de falso positivo (PEM em código de parser,
  chaves Firebase, multidex, timestamp de zipalign) para travar o
  comportamento. (feito) A fixture do inventory cobre PEM só header, PEM
  completo/escapado e identificadores client-side; os testes de repack cobrem
  multidex/zipalign.
- Profundidade de obfuscação: pontuar string encryption além da detecção de
  Base64, deobfuscação server-side além do mapeamento de classe/arquivo e
  validação das cadeias de rotação v3 e source stamp.
- Recuperar versão de bibliotecas nativas via SONAME/nome do arquivo para OSV.

## Backends de decompilação

O pipeline hoje fixa o `jadx` como produtor da árvore. É a parte mais lenta e
frágil do run: timeout de 15 minutos e risco de OOM em APKs grandes.

### Candidato: `androguard/dex-decompiler`

O [androguard/dex-decompiler](https://github.com/androguard/dex-decompiler) é
um decompilador DEX → Java em Rust puro, da própria org do Androguard
(Apache-2.0). Propriedades relevantes:

- export de árvore completa (`-d out/`), compatível com o contrato atual de
  `SourceRoot`/gitleaks/semgrep/inventory;
- fast path de consulta (`--getclass`, `--findrefs`) sem índice global;
- análise de segurança embutida: `--scan-vulns`, `--scan-semgrep` (MASTG) e
  `--taint-solve` (taint interprocedural estilo Mariana Trench);
- API de biblioteca Rust e bindings Python;
- sem JVM e com pegada de memória baixa.

Ele **não** decodifica `res/` nem `resources.arsc`, então não substitui o
`apktool` para resources. O parser nativo de AXML/arsc do P1 é o complemento.

### Forma de integração (implementada)

- `--decompiler jadx|dexdc|both|a,b`, padrão `jadx`; `both` mantém o
  significado histórico `apktool+jadx` e `jadx,dexdc` extrai as duas árvores.
- Estágio opcional `dexdc` (binário `dex-decompile`), fail-soft, timeout de
  15 min, entrada em `allowedBinaries`, saída em `<session>/dexdc/`.
- `SourceRoot` resolve `jadx → apktool → dexdc → raiz da sessão`; um run
  `jadx,dexdc` escaneia a árvore de referência do jadx.
- Converters de `--scan-vulns`/`--taint-output` ficam adiados até a avaliação
  diferencial passar; depois viram findings `SourceTool=dexdc` com mapeamento
  de categoria e dedup por regra/MASVS.
- O `jadx` continua como backend de referência/padrão até a avaliação abaixo
  passar. O wrapper e o harness estão implementados; o run diferencial ainda
  precisa ser executado nos artefatos escolhidos antes de mudar o padrão.

Veja o [ADR-009](adr/009-decompiler-backends.md).

### Harness de avaliação (critérios de aceite)

Implementado como `scripts/evaluate-decompiler.py <apk>` (runbook manual, fora
do `go test`). Ele roda os dois backends em workdirs separados e emite tempo
de parede, tempo do decompilador, RSS de pico, contagem de findings, recall
por categoria+título+evidência, overlap de fingerprint estrito e notificações
de erro do semgrep, além de PASS/FAIL para os critérios abaixo. Rodar os dois
backends no mesmo APK (começando por um alvo real grande) e comparar:

| Métrica | Meta |
|---------|------|
| Recall de findings conhecidos (secrets, pinning, manifest) | ≥ 95% do run com jadx |
| Taxa de erro de parse do semgrep na árvore emitida | < 5% |
| Tempo de export da árvore completa (APK de 230 MB) | < 30 s |
| RSS de pico | < 1 GB |
| IDs do `findings.json` | estáveis ou mudança documentada |
| `--findrefs` em 20 sinks conhecidos | classe/método corretos em todos |

Não promover o backend a padrão só com benchmark; o resultado diferencial é a
entrada da decisão.

### Riscos

- Tanto o decompilador quanto seus scanners são jovens (0.1.x); saída e
  semântica das regras podem mudar. Pine um commit exato e mantenha o `jadx`.
- Pseudocódigo que o semgrep não parseia gera falso negativo silencioso.
- Taint engines podem ter falso positivo e, pior, falso negativo; trate a saída
  como fonte adicional com confiança própria.
- Backend novo pode mudar arquivo/linha e, portanto, os IDs determinísticos.
  Decida entre normalizar a localização para classe/método ou aceitar migração.
- Sem releases publicados: compile de um commit pinado, versione o
  `Cargo.lock`, rode `cargo audit` e mantenha o toolchain em um stage Docker
  separado.

## Ordem sugerida

1. P0 (feito) — tornar o relatório legível.
2. P1 (feito) — parse nativo de manifest/DEX, NSC completo, checks de
   targetSdk e origem do finding.
3. P2 diff/baseline/gate de CI (feito).
4. P2 Kotlin/taint, verificação de assinatura, profundidade nativa e
   detecção de SDK (feito).
5. P3 performance/relatório (feito).
6. Avaliação do backend de decompilação, depois `--fast`.
