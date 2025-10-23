Perfeito! Aqui está o **Relatório 15** ajustado para **apenas duas VMs** (**pfSense** e **VM1**), com o IDS alertando **tráfego entre a Internet e a VM1** (sem VM2, sem tráfego lateral).

---

# T02 – Redes de Dados I

# Relatório 15: Configuração de **IDS** de Rede usando **pfSense + Suricata** (sem IPS). Análise de funcionamento — **VM1 ↔ Internet**

Este relatório descreve a configuração de um **IDS (Intrusion Detection System)** com **Suricata** no **pfSense**, monitorando **uma única LAN** com **duas VMs**: **pfSense** (gateway e sensor) e **VM1 (Debian Desktop — GUI)**. O objetivo é **montar o ambiente**, habilitar o Suricata em **modo IDS (somente alerta, sem bloqueios)**, **gerar tráfego didático e inofensivo** da **VM1 para a Internet** e **analisar os alertas** no pfSense.

> **Importante:** este relatório **não** cobre IPS (bloqueio). Todos os cenários são **seguros e reprodutíveis** no laboratório.

---

## I. Introdução

O **pfSense** atuará como **gateway/NAT** e **sensor IDS** na interface **LAN**, analisando **somente o tráfego VM1↔Internet**. Usaremos **ET Open rules** e algumas **regras locais (alert)** para garantir alertas didáticos e reprodutíveis.

**Pilares:** **Confidencialidade** e **Monitoramento/Detecção**, com ênfase em **auditoria** e **visibilidade** do tráfego.

---

## II. Conceitos e Fundamentos

* **Firewall x IDS:** o firewall **impõe** política (permite/bloqueia) quando está **no caminho** do tráfego; o **IDS** é **passivo**, apenas **observa e alerta**.
* **Suricata (DPI):** inspeção profunda baseada em **regras/assinaturas**: **ET Open** (público) e **regras locais** (custom).
* **HTTPS:** conteúdo cifrado; o IDS enxerga **metadados** (ex.: **SNI**), diferente de **HTTP**, onde consegue ver cabeçalhos/corpo.
* **Promiscuous Mode:** **não é necessário** neste cenário (apenas VM1 na LAN), mas pode ser mantido sem prejuízo.

---

## III. Ambiente e Topologia

**VirtualBox (2 VMs):**

* **VM-pfSense**

  * **Adapter 1 (WAN):** **NAT** (DHCP do VBox)
  * **Adapter 2 (LAN):** **Internal Network** **`LAN_PFS`**
  * *(Opcional)* **Adapter 2 → Avançado → Promiscuous Mode:** **Allow All** (não obrigatório aqui)

* **VM1 (Debian Desktop — GUI, LAN)**

  * **Adapter 1:** **Internal Network** **`LAN_PFS`** (IP via **DHCP** do pfSense)
  * Navegador gráfico (Firefox/Chromium) e utilitários de rede

> **Assunção do lab:** pfSense com **LAN** `192.168.1.1/24` (DHCP ativo). Não cobrimos o “primeiro setup” do pfSense.

---

## IV. Instalação e Preparação

### 0) **Preparar as redes (Configurações das VMs)**

1. **pfSense — habilitar 2 interfaces**

* VirtualBox → **botão direito** na VM **pfSense** → **Configurações** → **Rede**.
  **Adaptador 1 (WAN):** **Habilitar** ✔️ → **Conectado a:** **NAT**
  **Adaptador 2 (LAN):** **Habilitar** ✔️ → **Internal Network** → **Nome:** **`LAN_PFS`**
  *(Opcional)* **Avançado → Promiscuous Mode:** **Allow All**
  **OK**.

2. **VM1 — conectar na mesma LAN**

* **VM1** → **Configurações** → **Rede** → **Adapter 1 = Internal Network** **`LAN_PFS`** → **OK**.

3. **Verificação rápida (VM1)**

```bash
ip a                    # deve obter IP 192.168.1.x
ping -c2 192.168.1.1    # gateway LAN (pfSense)
ping -c2 1.1.1.1        # checar saída para internet
```

### A) VM1 (Debian Desktop — GUI)

Instalar utilitários e navegador (se necessário):

```bash
sudo apt update && sudo apt install -y dnsutils net-tools curl wget
sudo apt install -y firefox-esr   # (ou: sudo apt install -y chromium)
```

### B) pfSense — instalar e preparar o Suricata (IDS)

1. **Instalar Suricata**
   *System > Package Manager > Available Packages* → **suricata** → *Install* → *Confirm*

2. **Global Settings (ET Open)**
   *Services > Suricata > Global Settings*

* **Install ETOpen:** **Enable**
* **Update Interval:** ex. **12 hours**
* *Save* → **Update Rules** (aguarde o download)

3. **Adicionar interface LAN (IDS)**
   *Services > Suricata > Interfaces* → **Add**

* **Interface:** **LAN**
* **IPS Mode:** **Off** (apenas IDS)
* **Promiscuous Mode:** **Off** (suficiente aqui)
* **Block Offenders:** **Disabled**
* **Home Net:** padrão (LAN)
* *Save* → na lista, **Enable** a interface **LAN** e clique **Start**.

4. **Categorias de regras** (sugeridas)

* *Services > Suricata > Interfaces > [LAN] > Categories*

  * Ative: **ET POLICY**, **ET DNS**, **ET MALWARE** *(e **ET WEB_SERVER**, se quiser mais ruído didático)*.
  * *Save* / *Apply*.

5. **Regras locais (apenas `alert`, reprodutíveis)**
   *Interfaces > [LAN] > Rules (ou Custom Rules)* — adicione:

```
# DNS: alerta quando resolver neverssl.com
alert dns $HOME_NET any -> any any (msg:"LAB IDS DNS neverssl.com"; dns.query; content:"neverssl.com"; nocase; sid:1000001; rev:1;)

# HTTP: alerta ao acessar neverssl.com em claro
alert http $HOME_NET any -> any any (msg:"LAB IDS HTTP neverssl.com"; http.host; content:"neverssl.com"; nocase; sid:1000002; rev:1;)

# TLS: alerta ao acessar example.com (SNI)
alert tls $HOME_NET any -> any any (msg:"LAB IDS TLS SNI example.com"; tls.sni; content:"example.com"; nocase; sid:1000003; rev:1;)

# User-Agent “scanner” (policy didático)
alert http $HOME_NET any -> any any (msg:"LAB IDS UA sqlmap"; http.user_agent; content:"sqlmap"; nocase; sid:1000004; rev:1;)

# (Opcional) ICMP Echo para Internet
alert icmp $HOME_NET any -> any any (msg:"LAB IDS ICMP Echo to Internet"; itype:8; sid:1000005; rev:1;)
```

*Save* / *Apply* e, se precisar, **Stop/Start** na interface LAN do Suricata.

> **SIDs locais:** use valores ≥ **1.000.000** (aqui usamos 1.000.001+).

---

## V. Procedimentos (Passo a Passo — IDS apenas, **VM1 ↔ Internet**)

> **Onde ver eventos:** *Services > Suricata > Alerts* (selecione **LAN**).
> Deixe a aba de **Alerts** aberta e clique **Refresh** após cada teste.

### Cenário 1 — **DNS para neverssl.com (benigno)**

**Objetivo:** validar visibilidade de **DNS** da VM1 para a Internet.

**VM1:**

```bash
dig neverssl.com +short
```

**pfSense (Alerts/LAN):**
Ver **alerta local** `LAB IDS DNS neverssl.com` (**sid:1000001**).
*(Se nada aparecer, confirme se a VM1 está usando o DNS via pfSense/roteamento.)*

---

### Cenário 2 — **HTTP em claro (neverssl.com)**

**Objetivo:** mostrar inspeção em **HTTP** (host visível).

**VM1:**

```bash
curl -I http://neverssl.com
```

**pfSense (Alerts/LAN):**
Ver **alerta local** `LAB IDS HTTP neverssl.com` (**sid:1000002**).
Possíveis alertas de **ET POLICY** dependendo do tráfego.

---

### Cenário 3 — **HTTPS (example.com) com SNI**

**Objetivo:** evidenciar que em **HTTPS** o IDS enxerga **metadados** (SNI), não o conteúdo.

**VM1:**

```bash
curl -I https://example.com
```

**pfSense (Alerts/LAN):**
Ver **alerta local** `LAB IDS TLS SNI example.com` (**sid:1000003**).
Observe que cabeçalhos/corpo **não** são visíveis (apenas SNI, JA3, etc.).

---

### Cenário 4 — **User-Agent “scanner” (policy, inofensivo)**

**Objetivo:** acionar **ET POLICY** (ou a **regra local** de UA) simulando um **User-Agent** típico de scanner.

**VM1:**

```bash
curl -A "sqlmap/1.7" http://neverssl.com
curl -A "Nikto/2.1.6" http://neverssl.com
```

**pfSense (Alerts/LAN):**
Ver alertas **ET POLICY** por **User-Agent suspeito** e/ou o local `LAB IDS UA sqlmap` (**sid:1000004**).

---

### Cenário 5 — **EICAR (teste anti-malware, seguro)**

**Objetivo:** acionar assinatura **ET MALWARE** com o padrão **EICAR** (arquivo de **teste**).

**VM1 (download via HTTP):**

```bash
# Download direto do teste EICAR (arquivo de texto, seguro)
curl -L http://www.eicar.org/download/eicar.com.txt -o /tmp/eicar.txt
```

**pfSense (Alerts/LAN):**
Ver alerta **ET MALWARE / EICAR** (nome pode variar conforme regra).

> *Se seu ambiente bloquear o domínio acima, tente “[http://www.eicar.org/download/eicar.com”](http://www.eicar.org/download/eicar.com”) ou refaça depois desabilitando cache/AV na VM1 apenas para o teste.*

---

### (Opcional) Cenário 6 — **ICMP Echo para Internet**

**Objetivo:** gerar alerta **local** simples de **ICMP**.

**VM1:**

```bash
ping -c2 1.1.1.1
```

**pfSense (Alerts/LAN):**
Ver alerta `LAB IDS ICMP Echo to Internet` (**sid:1000005**).

---

## VI. Verificação e Resultados

### 1) Quadro comparativo (cenários)

| Cenário | Tráfego                       | Regras envolvidas                                              | Resultado esperado | Onde verificar            |
| :-----: | :---------------------------- | :------------------------------------------------------------- | :----------------- | :------------------------ |
|    1    | VM1 → Internet (DNS)          | **Local:** `LAB IDS DNS neverssl.com`                          | **Alertas**        | Suricata **Alerts** (LAN) |
|    2    | VM1 → Internet (HTTP)         | **Local:** `LAB IDS HTTP neverssl.com` (+ poss. **ET POLICY**) | **Alertas**        | Alerts (LAN)              |
|    3    | VM1 → Internet (HTTPS)        | **Local:** `LAB IDS TLS SNI example.com`                       | **Alertas**        | Alerts (LAN)              |
|    4    | VM1 → Internet (UA “scanner”) | **ET POLICY** e/ou **Local (UA sqlmap)**                       | **Alertas**        | Alerts (LAN)              |
|    5    | VM1 → Internet (EICAR)        | **ET MALWARE** (EICAR)                                         | **Alertas**        | Alerts (LAN)              |
|    6*   | VM1 → Internet (ICMP)         | **Local:** `LAB IDS ICMP Echo to Internet`                     | **Alertas**        | Alerts (LAN)              |

* Cenário 6 é opcional.

### 2) O que registrar

* **Timestamp**, **Interface**, **Categoria**, **SID**, **SRC→DST IP:Porta**, **Proto**, **mensagem (msg)** da regra.
* Prints da aba **Alerts** por cenário.

---

## VII. Conclusão

Com **pfSense + Suricata** em **modo IDS**, obtivemos **visibilidade** sobre tráfego **VM1↔Internet**, gerando **alertas** com **ET Open** e **regras locais**. Em **HTTP**, o IDS enxerga host/cabeçalhos; em **HTTPS**, observa **metadados** (ex.: SNI). O laboratório demonstra **auditoria** e **correlação** de eventos **sem** realizar testes invasivos, mantendo o foco em **didática e segurança**.

---

## Apêndice — Troubleshooting rápido

* **Sem alertas:** confirme que a interface **LAN** do Suricata está **Enabled/Started** e que a VM1 **sai à Internet** via pfSense (NAT). Gere tráfego **após** iniciar o serviço e **atualize as regras** (ET Open).
* **DNS/HTTP/HTTPS locais não disparam:** confira as **regras locais** (SIDs e `content`), salve e *Apply*, e **Refresh** na aba Alerts.
* **EICAR não aparece:** verifique **ET MALWARE** habilitado; baixe novamente (limpe cache com `-H "Cache-Control: no-cache"`); alguns ambientes bloqueiam o domínio — teste outra URL do EICAR.
* **UA “scanner” sem alerta:** mantenha a **regra local** de UA; em ET POLICY, nem todas as assinaturas disparam em todos os hosts.
* **Uso de CPU:** desative categorias desnecessárias; mantenha **IDS (IPS OFF)**.

---

Se quiser, eu já **gero um PDF** ou adiciono um **checklist resumido** ao final. Quer também um **diagrama simples da topologia** para anexar?
