# T02 – Redes de Dados I

# Relatório 15: Configuração de **IDS** de Rede usando **pfSense + Suricata** (sem IPS). Análise de funcionamento

Este relatório descreve a configuração de um **IDS (Intrusion Detection System)** com **Suricata** no **pfSense**, monitorando uma única LAN com **três VMs**: **pfSense** (gateway e sensor), **VM1 (Debian Desktop — GUI)** e **VM2 (Debian Desktop — GUI)**. O objetivo é **montar o ambiente**, habilitar o Suricata em **modo IDS (somente alerta, sem bloqueios)**, **gerar tráfego didático e inofensivo** e **analisar os alertas** no pfSense.

> **Importante:** este relatório **não** cobre IPS (bloqueio). Todos os cenários são **seguros e reprodutíveis** no laboratório.

---

## I. Introdução

O **pfSense** atuará como **gateway/NAT** e **sensor IDS** na interface **LAN**, analisando tráfego **VM1↔VM2** e **VM1↔Internet**. Usaremos **ET Open rules** e algumas **regras locais (alert)** apenas para garantir alertas didáticos.

**Pilares:** **Confidencialidade** e **Monitoramento/Detecção**, com ênfase em **auditoria** e **visibilidade** do tráfego.

---

## II. Conceitos e Fundamentos

* **Firewall x IDS:** o firewall **impõe** política (permite/bloqueia) quando está **no caminho** do tráfego; o **IDS** é **passivo**, apenas **observa e alerta** (off-path/copiado).
* **Suricata (DPI):** inspeção profunda baseada em **regras/assinaturas**: **ET Open** (público) e **regras locais** (custom).
* **HTTPS:** conteúdo é cifrado; o IDS enxerga **metadados** (ex.: **SNI**), diferente de **HTTP**, onde consegue ver cabeçalhos e corpo.
* **Promiscuous Mode:** necessário para que o pfSense **veja também** tráfego **VM1↔VM2** na mesma LAN (camada 2).

---

## III. Ambiente e Topologia

**VirtualBox (3 VMs):**

* **VM-pfSense**

  * **Adapter 1 (WAN):** **NAT** (DHCP do VBox)
  * **Adapter 2 (LAN):** **Internal Network** **`LAN_PFS`**
  * **(Recomendado)**: em **Adapter 2 → Avançado → Promiscuous Mode:** **Allow All**

* **VM1 (Debian Desktop — GUI, LAN)**

  * **Adapter 1:** **Internal Network** **`LAN_PFS`** (IP via **DHCP** do pfSense)
  * Navegador gráfico (Firefox/Chromium) para os testes

* **VM2 (Debian Desktop — GUI, LAN)**

  * **Adapter 1:** **Internal Network** **`LAN_PFS`** (IP via **DHCP** do pfSense)
  * Serviço **Apache HTTP** simples para os cenários

> **Assunção do lab:** pfSense com **LAN** `192.168.1.1/24` (DHCP ativo). Não cobrimos o “primeiro setup” do pfSense.

---

## IV. Instalação e Preparação

### 0) **Preparar as redes (criando pelas Configurações das VMs)**

1. **pfSense — habilitar 2 interfaces**

* VirtualBox → **botão direito** na VM **pfSense** → **Configurações** → **Rede**.
* **Adaptador 1 (WAN):** **Habilitar** ✔️ → **Conectado a:** **NAT**
* **Adaptador 2 (LAN):** **Habilitar** ✔️ → **Internal Network** → **Nome:** **`LAN_PFS`**

  * **Avançado → Promiscuous Mode:** **Allow All**
* **OK**.

2. **VM1 e VM2 — conectar na mesma LAN**

* **Botão direito** em **VM1** → **Configurações** → **Rede** → **Adapter 1 = Internal Network** **`LAN_PFS`** → **OK**.
* Repita para **VM2**.

3. **Verificação rápida (VM1/VM2)**

```bash
# Em cada VM
ip a                 # deve obter IP 192.168.1.x
ping -c2 192.168.1.1 # gateway LAN (pfSense)
```

### A) VM1 e VM2 (Debian Desktop — GUI)

Instalar utilitários e navegador (se necessário):

```bash
# Em ambas (VM1 e VM2)
sudo apt update && sudo apt install -y dnsutils net-tools curl

# Navegador gráfico (caso falte)
sudo apt install -y firefox-esr   # (ou: sudo apt install -y chromium)
```

Na **VM2**, disponibilize uma página HTTP simples:

```bash
sudo apt install -y apache2
echo "<h1>HELLO_IDS_ONLY_VM2</h1>" | sudo tee /var/www/html/index.html
sudo systemctl enable --now apache2
```

### B) pfSense — instalar e preparar o Suricata (IDS)

1. **Instalar Suricata**
   *System > Package Manager > Available Packages* → **suricata** → *Install* → *Confirm*

2. **Global Settings (ET Open)**

   * *Services > Suricata > Global Settings*

     * **Install ETOpen:** **Enable**
     * **Update Interval:** ex. **12 hours**
     * *Save* → **Update Rules** (aguarde o download)

3. **Adicionar interface LAN (IDS)**

   * *Services > Suricata > Interfaces* → **Add**

     * **Interface:** **LAN**
     * **IPS Mode:** **Off** (apenas IDS)
     * **Promiscuous Mode:** **On** (para ver VM1↔VM2)
     * **Block Offenders:** **Disabled**
     * **Home Net:** padrão (LAN)
     * *Save*
   * Na lista, **Enable** a interface LAN e clique **Start**.

4. **Categorias de regras** (sugeridas para o lab)

   * *Services > Suricata > Interfaces > [LAN] > Categories*

     * Ative: **ET POLICY**, **ET WEB_SERVER**, **ET MALWARE**.
     * *Save* / *Apply*.

5. **Regras locais (opcional, apenas `alert`)**
   Para garantir alertas reprodutíveis, adicione **apenas regras `alert`** (sem `drop`):

   * *Interfaces > [LAN] > Rules (ou Custom Rules)*:

     ```
     # Acesso HTTP à VM2 (garante alerta ao abrir a página da VM2)
     alert tcp $HOME_NET any -> <IP_VM2> 80 (msg:"LAB IDS VM2 HTTP access"; flow:to_server,established; sid:1000001; rev:1;)

     # HTTP host neverssl.com (alerta didático; tráfego comum)
     alert http any any -> any any (msg:"LAB IDS HTTP neverssl"; http.host; content:"neverssl.com"; nocase; sid:1000002; rev:1;)

     # TLS SNI example.com (alerta didático em HTTPS)
     alert tls any any -> any any (msg:"LAB IDS TLS SNI example.com"; tls.sni; content:"example.com"; nocase; sid:1000003; rev:1;)
     ```

   *Save* / *Apply* e, se precisar, **Stop/Start** na interface LAN do Suricata.

> **SIDs locais:** use valores ≥ **1.000.000** se a sua versão exigir; aqui usamos 1.000.001+ por segurança didática.

---

## V. Procedimentos (Passo a Passo — IDS apenas)

> **Onde ver eventos:** *Services > Suricata > Alerts* (selecione **LAN**).
> Deixe a aba de **Alerts** aberta e clique **Refresh** após cada teste.

### Cenário 1 — **Acesso HTTP à VM2 (benigno e local)**

**Objetivo:** validar que o IDS “vê” tráfego **VM1↔VM2** na mesma LAN.

1. **VM1 (navegador):**

   * Abra **http://<IP_VM2>/** → deve carregar `HELLO_IDS_ONLY_VM2`.
2. **pfSense (Alerts/LAN):**

   * Ver **alerta local** `LAB IDS VM2 HTTP access` (regra `sid:1000001`)
   * Possíveis alertas **ET WEB_SERVER** (dependendo das categorias).

> *Se nada aparecer:* confirme **Promiscuous = On** no Suricata e **Allow All** na NIC LAN do pfSense (VirtualBox).

---

### Cenário 2 — **User-Agent “suspeito” (policy, inofensivo)**

**Objetivo:** disparar **ET POLICY** com um **User-Agent** comum em scanners (sem escanear nada).

1. **VM1 → VM2 (UA customizado):**

```bash
curl -A "sqlmap/1.7" http://<IP_VM2>/
curl -A "Nikto/2.1.6" http://<IP_VM2>/
```

2. **pfSense (Alerts/LAN):**

   * Ver alertas **ET POLICY** por **User-Agent suspeito**.

---

### Cenário 3 — **Método HTTP TRACE (policy)**

**Objetivo:** acionar regra de política por método HTTP incomum.

1. **VM1 → VM2:**

```bash
curl -v -X TRACE http://<IP_VM2>/
```

2. **pfSense (Alerts/LAN):**

   * Ver alertas **ET POLICY** relacionados a **TRACE**.

---

### Cenário 4 — **Padrões genéricos de XSS/SQLi (didático, seguro)**

**Objetivo:** gerar alertas **ET WEB_SERVER** com *strings* típicas (apenas texto).

1. **VM1 → VM2 (URLs com payloads simples):**

```bash
# XSS (URL-encoded)
curl "http://<IP_VM2>/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# SQLi genérica
curl "http://<IP_VM2>/index.php?id=1%20UNION%20SELECT%201,2,3"
```

2. **pfSense (Alerts/LAN):**

   * Ver alertas **ET WEB_SERVER** (XSS/SQLi genéricos) — se não houver, as regras locais dos cenários 1/5 garantem visibilidade.

---

### Cenário 5 — **EICAR (teste anti-malware, texto seguro)**

**Objetivo:** acionar assinatura **ET MALWARE** com o padrão **EICAR** (arquivo de **teste**, não é malware).

1. **VM2 (servir eicar.txt):**

```bash
sudo sh -c 'echo "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" > /var/www/html/eicar.txt'
```

2. **VM1 (baixar o arquivo):**

```bash
curl http://<IP_VM2>/eicar.txt -o /dev/null
```

3. **pfSense (Alerts/LAN):**

   * Ver alerta **ET MALWARE / EICAR**.

---

### (Opcional) Cenário 6 — **Navegação comum (internet) com alertas locais**

**Objetivo:** mostrar que o IDS também observa **VM1↔Internet**.

1. **VM1 (navegador):**

   * **[http://neverssl.com](http://neverssl.com)** (HTTP claro)
   * **[https://example.com](https://example.com)** (HTTPS)
2. **pfSense (Alerts/LAN):**

   * Ver alertas **locais**: `LAB IDS HTTP neverssl` e `LAB IDS TLS SNI example.com` (se adicionados).
   * Em HTTPS, note que o conteúdo é cifrado (apenas metadados, ex.: SNI).

---

## VI. Verificação e Resultados

### 1) Quadro comparativo (cenários)

| Cenário | Tráfego                      | Regras envolvidas                                            | Resultado esperado | Onde verificar            |
| :-----: | :--------------------------- | :----------------------------------------------------------- | :----------------- | :------------------------ |
|    1    | VM1 → VM2 (HTTP)             | **Local:** `LAB IDS VM2 HTTP access` (+ poss. ET WEB_SERVER) | **Alertas**        | Suricata **Alerts** (LAN) |
|    2    | VM1 → VM2 (User-Agent)       | **ET POLICY** (UA suspeito)                                  | **Alertas**        | Alerts (LAN)              |
|    3    | VM1 → VM2 (HTTP TRACE)       | **ET POLICY** (método TRACE)                                 | **Alertas**        | Alerts (LAN)              |
|    4    | VM1 → VM2 (XSS/SQLi strings) | **ET WEB_SERVER** (padrões genéricos)                        | **Alertas**        | Alerts (LAN)              |
|    5    | VM1 → VM2 (EICAR)            | **ET MALWARE** (EICAR)                                       | **Alertas**        | Alerts (LAN)              |
|    6*   | VM1 → Internet (HTTP/HTTPS)  | **Locais** (neverssl/example.com)                            | **Alertas**        | Alerts (LAN)              |

* Cenário 6 é opcional.

### 2) O que registrar

* **Timestamp**, **Interface**, **Categoria**, **SID**, **SRC→DST IP:Porta**, **Proto**, **mensagem (msg)** da regra.
* Prints da aba **Alerts** por cenário.

---

## VII. Conclusão

Com **pfSense + Suricata** em **modo IDS**, obtivemos **visibilidade** sobre tráfego **VM1↔VM2** e **VM1↔Internet**, gerando **alertas** com **ET Open** e **regras locais**. Em **HTTP**, o IDS enxerga cabeçalhos/conteúdo; em **HTTPS**, observa **metadados** (ex.: SNI). O laboratório mostra como **auditar** e **correlacionar** eventos sem realizar testes invasivos ou instrutivos de ataque.

---

## Anexos (inserir prints)

* **Figura 1 —** Topologia: pfSense (WAN=NAT, LAN=`LAN_PFS`), **VM1** e **VM2** na mesma LAN.
* **Figura 2 —** Suricata **Global Settings** com **ETOpen** habilitado e regras atualizadas.
* **Figura 3 —** Interface **LAN** do Suricata **Enabled/Started** (IDS, Promiscuous=On).
* **Figura 4 —** **Alerts** do Cenário 1 (acesso HTTP à VM2).
* **Figura 5 —** **Alerts** dos Cenários 2–4 (POLICY/WEB_SERVER).
* **Figura 6 —** **Alert** do Cenário 5 (EICAR).
* **Figura 7 —** (Opcional) **Alerts** com navegação comum (neverssl/example.com).

---

## Apêndice — Troubleshooting rápido

* **Sem alertas:** confirme **Promiscuous = On** (Suricata/LAN) e **Allow All** na NIC LAN do pfSense (VirtualBox). Gere tráfego **após** iniciar o serviço e atualize as **regras** (ET Open).
* **Cenários 2–4 sem disparo:** garanta que as categorias **ET POLICY/ET WEB_SERVER** estão **Ativas**; copie os comandos exatamente (UA, TRACE, URLs).
* **EICAR não aparece:** verifique **ET MALWARE** habilitado; rebaixe o arquivo (limpe cache); confira se o path `eicar.txt` está correto.
* **Nada aparece ao acessar VM2:** confira o **IP da VM2** e a **regra local** `LAB IDS VM2 HTTP access`; reabra a página pelo IP.
* **Apenas HTTPS “sem detalhes”:** comportamento esperado — TLS cifra o conteúdo; use regras por **SNI** (local) para fins didáticos.
* **Uso de CPU:** desative categorias que não precisa; mantenha somente **IDS (IPS OFF)**.

Pronto — IDS puro, **didático e seguro**. Quer que eu gere a versão em PDF ou com um checklist resumido ao final?
