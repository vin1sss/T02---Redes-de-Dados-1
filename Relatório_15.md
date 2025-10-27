# T02 – Redes de Dados I

# Relatório 15: Configuração de **IDS** de Rede usando **pfSense + Suricata**. Análise de funcionamento

Este relatório descreve a configuração de um **IDS (Intrusion Detection System)** com **Suricata** no **pfSense**, monitorando **uma LAN** com **duas VMs**: **pfSense** (gateway e sensor) e **VM1 (Debian Desktop — GUI)**. O objetivo é **montar o ambiente**, habilitar o Suricata em **modo IDS (somente alerta, sem bloqueios)**, **gerar tráfego didático e inofensivo** da **VM1 para a Internet** e **analisar os alertas** no pfSense.

> **Importante:** Todos os cenários são **seguros e reprodutíveis** no laboratório.

---

## I. Introdução

O **pfSense** atuará como **gateway/NAT** e o **Suricata** atuará como **sensor IDS** na interface **LAN**, analisando **o tráfego VM1↔Internet**. Usaremos **regras locais (Custom Rules)** para garantir alertas didáticos e reprodutíveis.

**Pilares:** **Confidencialidade** e **Monitoramento/Detecção**, com ênfase em **auditoria** e **visibilidade** do tráfego.

---

## II. Conceitos e Fundamentos

* **Firewall x IDS:** o firewall **impõe** política (permite/bloqueia) quando está **no caminho** do tráfego; o **IDS** é **passivo**, apenas **observa e alerta**.
* **Suricata (DPI):** inspeção profunda baseada em **regras/assinaturas**, aqui usando **regras locais** definidas pelo analista.
* **HTTPS:** conteúdo cifrado; o IDS enxerga **metadados** (ex.: **SNI**), diferente de **HTTP**, onde consegue ver cabeçalhos/corpo.

---

## III. Ambiente e Topologia

**VirtualBox (2 VMs):**

* **VM-pfSense**

  * **Adapter 1 (WAN):** **NAT** (DHCP do VBox)
  * **Adapter 2 (LAN):** **Internal Network** **`LAN_PFS`**

* **VM1 (Debian Desktop — GUI, LAN)**

  * **Adapter 1:** **Internal Network** **`LAN_PFS`** (IP via **DHCP** do pfSense)

---

## IV. Instalação e Preparação

### 0) **Preparar as redes (Configurações das VMs)**

1. **pfSense — habilitar 2 interfaces**

* VirtualBox → **botão direito** na VM **pfSense** → **Configurações** → **Rede**.
  **Adaptador 1 (WAN):** **Habilitar** → **Conectado a:** **NAT**
  **Adaptador 2 (LAN):** **Habilitar** → **Internal Network** → **Nome:** **`LAN_PFS`**
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

[![image.png](https://i.postimg.cc/DfsHJvr1/image.png)](https://postimg.cc/JtrPSWdh)

### A) VM1 (Debian Desktop — GUI)

Instalar utilitários (opcional, para diagnósticos):

```bash
sudo apt update && sudo apt install -y dnsutils net-tools curl wget
```

### B) pfSense — instalar e preparar o Suricata (IDS)

> Acessar a interface gráfica do pfSense no navegador: `http://192.168.1.1`

0. **Instalar Suricata:**
   *System > Package Manager > Available Packages* → **suricata** → *Install* → *Confirm*

1. **(Importante) Desabilitar downloads de rules externos**
   *Services > Suricata > Global Settings* → deixe **desmarcadas** opções de **Download/Update** de rules (não habilitar ET/OpenAppID/etc.).

2. **Adicionar interface LAN (IDS)**
   *Services > Suricata > Interfaces* → **Add**

* **Interface:** **LAN**
* **IPS Mode:** **Off** (apenas IDS)
* **Promiscuous Mode:** **Off**
* **Block Offenders:** **Disabled**
* **Home Net:** padrão (LAN)
* *Save* → na lista, **Enable** a interface **LAN** e clique **Start**.

3. **Regras locais (apenas `alert`, reprodutíveis — testáveis via navegador)**
   *Services > Suricata > Interfaces > LAN > Edit > Rules (ou Local/Custom Rules)* — adicione:

```
# 1) HTTP: URI contendo string de trigger (dispara ao acessar URL com esse path)
alert http $HOME_NET any -> any any (msg:"CUSTOM BROWSER - HTTP URI trigger"; flow:established,to_server; http_uri; content:"/SURICATA_BROWSER_URI_01"; nocase; sid:1002001; rev:1; classtype:web-application-attack; priority:2;)

# 2) HTTP: corpo (client body) contendo string de trigger (dispara ao enviar POST/PUT com o texto)
alert http $HOME_NET any -> any any (msg:"CUSTOM BROWSER - HTTP client body trigger"; flow:established,to_server; http_client_body; content:"SURICATA_BROWSER_BODY_02"; nocase; sid:1002002; rev:1; classtype:web-application-attack; priority:2;)

# 3) HTTP: header custom (dispara quando request tem o header X-Trigger-Lab)
alert http $HOME_NET any -> any any (msg:"CUSTOM BROWSER - HTTP header X-Trigger-Lab"; flow:established,to_server; http_header; content:"X-Trigger-Lab|3a| 1"; nocase; sid:1002003; rev:1; classtype:attempted-recon; priority:2;)

# 4) DNS: query para domínio de trigger (dispara na consulta DNS gerada pelo navegador)
alert udp $HOME_NET any -> any 53 (msg:"CUSTOM BROWSER - DNS query trigger"; dns_query; content:"suricata-trigger-lab.example"; nocase; sid:1002004; rev:1; classtype:attempted-recon; priority:3;)
```

*Save* / *Apply* e, se precisar, **Stop/Start** na interface LAN do Suricata.

> **SIDs locais:** use valores ≥ **1.000.000** (aqui usamos 1.002.001+).

---

## V. Procedimentos (Passo a Passo — IDS, **VM1 ↔ Internet**)

> **Onde ver eventos:** *Services > Suricata > Alerts* (selecione **LAN**).
> Deixe a aba de **Alerts** aberta e clique **Refresh** após cada teste.

### Cenário 1 — **HTTP URI (navegador)**

**Objetivo:** validar inspeção de **URI** em HTTP.

**VM1 (navegador):** acesse na barra de endereços (pode ser qualquer site HTTP público, ex.: example.com):

```
http://example.com/SURICATA_BROWSER_URI_01
```

**pfSense (Alerts/LAN):**
Ver **alerta local** `CUSTOM BROWSER - HTTP URI trigger` (**sid:1002001**).

---

### Cenário 2 — **HTTP Body via navegador (POST)**

**Objetivo:** acionar regra por **corpo** da requisição.

**VM1 (navegador → DevTools → Console):**

```js
fetch('http://example.com/', { method: 'POST', body: 'SURICATA_BROWSER_BODY_02' }).catch(()=>{})
```

**pfSense (Alerts/LAN):**
Ver **alerta local** `CUSTOM BROWSER - HTTP client body trigger` (**sid:1002002**).

---

### Cenário 3 — **Header custom via navegador**

**Objetivo:** acionar regra por **cabeçalho HTTP**.

**VM1 (navegador → DevTools → Console):**

```js
fetch('http://example.com/', { method: 'GET', headers: { 'X-Trigger-Lab': '1' } }).catch(()=>{})
```

**pfSense (Alerts/LAN):**
Ver **alerta local** `CUSTOM BROWSER - HTTP header X-Trigger-Lab` (**sid:1002003**).

---

### Cenário 4 — **DNS (resolução de domínio de teste)**

**Objetivo:** validar que o Suricata enxerga a **consulta DNS**.

**VM1 (navegador):** acesse:

```
http://suricata-trigger-lab.example/
```

(mesmo que o site não exista, a **consulta DNS** é gerada)

**pfSense (Alerts/LAN):**
Ver **alerta local** `CUSTOM BROWSER - DNS query trigger` (**sid:1002004**).

---

## VI. Verificação e Resultados

### 1) Quadro comparativo (cenários)

| Cenário | Tráfego                      | Regras envolvidas                                       | Resultado esperado | Onde verificar            |
| :-----: | :--------------------------- | :------------------------------------------------------ | :----------------- | :------------------------ |
|    1    | VM1 → Internet (HTTP/URI)    | **Local:** `CUSTOM BROWSER - HTTP URI trigger`          | **Alertas**        | Suricata **Alerts** (LAN) |
|    2    | VM1 → Internet (HTTP/Body)   | **Local:** `CUSTOM BROWSER - HTTP client body trigger`  | **Alertas**        | Alerts (LAN)              |
|    3    | VM1 → Internet (HTTP/Header) | **Local:** `CUSTOM BROWSER - HTTP header X-Trigger-Lab` | **Alertas**        | Alerts (LAN)              |
|    4    | VM1 → Internet (DNS)         | **Local:** `CUSTOM BROWSER - DNS query trigger`         | **Alertas**        | Alerts (LAN)              |

### 2) O que registrar

* **Timestamp**, **Interface**, **Categoria**, **SID**, **SRC→DST IP:Porta**, **Proto**, **mensagem (msg)** da regra.
* Prints da aba **Alerts** por cenário.

---

## VII. Conclusão

Com **pfSense + Suricata** em **modo IDS** e **apenas regras locais**, obtivemos **visibilidade** sobre o tráfego **VM1↔Internet**, gerando **alertas** reprodutíveis com comandos simples via **navegador**. Em **HTTP**, o IDS enxerga URI, cabeçalhos e corpo; em **DNS**, observa as consultas. O laboratório demonstra **auditoria** e **correlação** de eventos **sem** rulesets externos e **sem** testes invasivos.

---

## Apêndice — Troubleshooting rápido

* **Sem alertas:** confirme que a interface **LAN** do Suricata está **Enabled/Started** e que a VM1 **sai à Internet** via pfSense (NAT). Gere tráfego **após** iniciar o serviço e **aplique** as regras locais.
* **Nada dispara nos cenários HTTP:** verifique se as URLs usam **HTTP** (não HTTPS) para os cenários de **URI/header/body**. Salve e *Apply* após editar regras.
* **DNS não aparece:** confirme que a VM1 usa o **pfSense como gateway/DNS** (ou que o tráfego DNS passa pela interface monitorada).
* **Uso de CPU:** mantenha somente as **regras locais necessárias**; IDS com poucas regras é leve.
* **Persistência das regras:** após atualizações do pacote, confirme se as **Local Rules** continuam carregadas e reaplique se necessário.
