# T02 – Redes de Dados I

# Relatório 14: Configuração de Firewall de Rede usando **pfSense** (VMs no VirtualBox)

Este relatório descreve a configuração de um **firewall pfSense** atuando como **gateway/NAT e filtro** para uma rede interna com **duas VMs**: **Cliente (Debian Desktop)** e **pfSense**. O objetivo é **montar o ambiente**, aplicar **regras de firewall** típicas e **validar o comportamento** por meio de testes práticos e análise de **logs** no pfSense.

---

## I. Introdução

Você irá configurar um **pfSense** com duas interfaces (WAN/LAN) no VirtualBox:

* **WAN**: sai para a Internet via **NAT** do VirtualBox.
* **LAN**: rede isolada (**Internal Network**) onde ficará a VM **Cliente** (Debian).

Depois, aplicará **regras de firewall** (ex.: bloqueio de HTTP, bloqueio de DNS externos, bloqueio de ICMP para Internet), testará com `curl`, `ping`, `dig` no Cliente e verificará **logs** no pfSense.
**Pilares abordados:** **Confidencialidade** e **Disponibilidade**, com ênfase em **Controle de Acesso** (políticas de saída) e **Registro/Auditoria** (logs).

---

## II. Conceitos e Fundamentos

* **Firewall stateful (pfSense):** avalia pacotes por **regras ordenadas (top-down)** e mantém **estado** de conexões.
* **NAT:** traduz IPs da LAN privada para o IP da WAN (saída para Internet).
* **Ordem de regras:** a **primeira regra que casa** com o tráfego decide o destino (ALLOW/DENY).
* **Logs:** permitem correlacionar **tentativas bloqueadas** e **permitidas** para auditoria.
* **Testes práticos:** `curl` (HTTP/HTTPS), `ping`/`ICMP`, `dig` (DNS).

---

## III. Ambiente e Topologia

**VirtualBox (2 VMs):**

* **VM-pfSense**

  * **Adapter 1 (WAN):** **NAT** (VirtualBox) – obtém IP via DHCP (ex.: `10.0.2.x`).
  * **Adapter 2 (LAN):** **Internal Network** chamada `LAN_PFS` (sem DHCP do VBox; pfSense fará DHCP).
* **VM-Cliente (Debian Desktop)**

  * **Adapter 1:** **Internal Network** `LAN_PFS` (IP via **DHCP do pfSense**).

**Endereçamento sugerido (LAN):**

* **pfSense LAN:** `192.168.10.1/24`
* **DHCP LAN (pfSense):** `192.168.10.100 – 192.168.10.200`
* **Cliente:** IP dinâmico (por ex. `192.168.10.100`)

> **Observação:** Diferente do Relatório 13 (NAT Network para ambas as VMs), aqui o pfSense **precisa de duas interfaces** (WAN e LAN). Por isso usamos **NAT** (WAN) + **Internal Network** (LAN).

---

## IV. Instalação e Preparação

### 0) Preparar as redes no VirtualBox

1. **Criar a LAN interna**

* VirtualBox → **Ferramentas** (*Tools*) → **Gerenciador de Redes** (*Network Manager*) → **Internal Networks**
* **Criar** uma Internal Network chamada **`LAN_PFS`** (sem DHCP do VBox).

2. **pfSense – associar interfaces**

* **Adapter 1 (WAN):** **Conectado a:** *NAT* (padrão).
* **Adapter 2 (LAN):** **Conectado a:** *Internal Network* → **Name:** `LAN_PFS`.

3. **Cliente (Debian) – associar interface**

* **Adapter 1:** **Conectado a:** *Internal Network* → **Name:** `LAN_PFS`.

4. **Inicialização e verificação (Cliente)**

```bash
ip a                 # deve receber IP 192.168.10.x após o DHCP do pfSense estar ativo
```

### A) pfSense — configuração inicial (via Console e WebGUI)

1. **Boot inicial (console pfSense):**

   * Confirme o mapeamento: **WAN = em0** (NAT), **LAN = em1** (`LAN_PFS`).
   * Defina **LAN IP**: `192.168.10.1/24`.
   * **Habilite DHCP** na LAN (range `192.168.10.100–192.168.10.200`).
   * Deixe **WAN = DHCP** (receberá IP do NAT do VirtualBox).

2. **Acesse a WebGUI (no Cliente):**

```bash
# no navegador do Cliente:
https://192.168.10.1
# ignore o alerta de certificado autoassinado
```

* Login padrão (pfSense “de fábrica”): **admin / pfsense** (altere após o lab).
* Conclua o **Setup Wizard**: confirme **WAN = DHCP**, **LAN = 192.168.10.1/24**, **DHCP LAN habilitado**.

3. **Teste de conectividade (Cliente):**

```bash
ping -c 2 192.168.10.1        # gateway (pfSense LAN)
curl -I http://example.com    # deve funcionar (HTTP)
curl -I https://example.com   # deve funcionar (HTTPS)
```

### B) Cliente (Debian Desktop)

Instale utilitários (se necessário):

```bash
sudo apt update && sudo apt install -y curl dnsutils net-tools
ip route
```

---

## V. Procedimentos (Passo a Passo)

> **Importante:** No pfSense, vá em **Firewall > Rules > LAN**. As regras são lidas **de cima para baixo**. Coloque as **regras de bloqueio acima** da regra “allow LAN to any”.

### Cenário 1 — Bloquear **HTTP (porta 80)** e permitir **HTTPS**

**Objetivo:** impedir navegação HTTP em claro; manter HTTPS funcional.

1. **pfSense (WebGUI) → Firewall > Rules > LAN → Add (setinha para cima):**

* **Action:** *Block*
* **Interface:** *LAN*
* **Address Family:** *IPv4*
* **Protocol:** *TCP*
* **Source:** *LAN net*
* **Destination:** *any*
* **Destination Port Range:** *HTTP (80)*
* **Description:** `BLOCK_LAN_HTTP_OUT`
* **Save** → **Apply Changes**

2. **Teste (Cliente):**

```bash
curl -v http://example.com        # deve FALHAR (bloqueado)
curl -v https://example.com       # deve OK
```

3. **Logs (pfSense):** **Status > System Logs > Firewall**, filtre por **Interface = LAN** e **porta 80**.
   Verifique entradas **blocked** oriundas do IP do Cliente.

---

### Cenário 2 — Bloquear **DNS externos**; permitir **DNS via pfSense**

**Objetivo:** forçar o uso do **DNS Resolver** do pfSense (Unbound na LAN) e bloquear consultas diretas a servidores externos (ex.: 8.8.8.8).

1. **pfSense → Services > DNS Resolver:**

   * **Enable** (padrão já vem ativo). Garanta que está **escutando na LAN**.

2. **pfSense → Firewall > Rules > LAN → Add (acima do allow):**

* **Action:** *Block*
* **Protocol:** *TCP/UDP*
* **Source:** *LAN net*
* **Destination:** *any*
* **Destination Port Range:** *DNS (53)*
* **Description:** `BLOCK_EXTERNAL_DNS`
* **Save** → **Apply Changes**

> (Como o DNS do pfSense é “LAN address:53”, esta regra bloqueia **destinos externos**. A resolução via **gateway (pfSense)** segue permitida pela regra allow LAN to any.)

3. **Teste (Cliente):**

```bash
dig @8.8.8.8 www.google.com    # deve FALHAR (bloqueado)
dig www.google.com             # deve RESOLVER via pfSense
```

4. **Logs:** **Status > System Logs > Firewall** → veja **blocks** para dest port **53**.

---

### Cenário 3 — Bloquear **ICMP para Internet**, permitir ICMP para o gateway

**Objetivo:** impedir `ping` para Internet (ex.: 8.8.8.8), mantendo o diagnóstico interno para o gateway.

1. **pfSense → Firewall > Rules > LAN → Add (acima do allow):**

* **Action:** *Block*
* **Protocol:** *ICMP*
* **ICMP subtypes:** *any*
* **Source:** *LAN net*
* **Destination:** *any*
* **Description:** `BLOCK_LAN_ICMP_INTERNET`
* **Save**

2. **Adicionar exceção para o gateway (opcional, acima do block):**

* **Action:** *Pass*
* **Protocol:** *ICMP*
* **Source:** *LAN net*
* **Destination:** *Single host or alias* → **192.168.10.1**
* **Description:** `ALLOW_ICMP_TO_GATEWAY`
* **Save** → **Apply Changes**

3. **Teste (Cliente):**

```bash
ping -c 2 8.8.8.8          # deve FALHAR
ping -c 2 192.168.10.1     # deve OK
```

4. **Logs:** ver **blocks** ICMP na saída.

---

### (Opcional) Cenário 4 — Permitir apenas “essenciais” (DNS+HTTPS) e bloquear o restante

**Objetivo:** política restritiva “**Allow list**” para tráfego de saída.

1. **pfSense → Firewall > Rules > LAN** (ordem de cima para baixo):

   * **Pass**: LAN → pfSense (LAN address) **DNS 53** (garante resolução)
   * **Pass**: LAN → *any* **HTTPS 443**
   * **Block**: LAN → *any* **any** (regra “drop all” final)
2. **Teste (Cliente):**

```bash
curl -I https://example.com     # OK
curl -I http://example.com      # BLOQUEADO
dig www.google.com              # OK (via pfSense)
curl -I http://ftp.debian.org   # BLOQUEADO (porta 80)
```

3. **Logs:** devem refletir os **drops** do que não está nos “essenciais”.

---

## VI. Verificação e Resultados

### 1) Quadro comparativo (cenários)

| Cenário | Tráfego            | Regra aplicada            | Resultado esperado | Validação (Cliente)                  |
| ------- | ------------------ | ------------------------- | ------------------ | ------------------------------------ |
| 1       | HTTP 80 (saída)    | `BLOCK_LAN_HTTP_OUT`      | **Bloqueado**      | `curl -v http://example.com` (falha) |
| 1       | HTTPS 443 (saída)  | Default allow             | **Permitido**      | `curl -v https://example.com` (ok)   |
| 2       | DNS 53 p/ externos | `BLOCK_EXTERNAL_DNS`      | **Bloqueado**      | `dig @8.8.8.8 ...` (falha)           |
| 2       | DNS via pfSense    | Resolver LAN              | **Permitido**      | `dig ...` (ok)                       |
| 3       | ICMP Internet      | `BLOCK_LAN_ICMP_INTERNET` | **Bloqueado**      | `ping 8.8.8.8` (falha)               |
| 3       | ICMP → gateway     | `ALLOW_ICMP_TO_GATEWAY`   | **Permitido**      | `ping 192.168.10.1` (ok)             |

### 2) Onde analisar

* **pfSense → Status > System Logs > Firewall** (filtre por **Interface = LAN**).
* Ordene por **Timestamp** para correlacionar com o momento do teste do Cliente.

---

## VII. Conclusão

Foi demonstrado, em ambiente controlado com **apenas duas VMs**, que o **pfSense** pode aplicar **políticas de saída** granulares (HTTP, DNS, ICMP), atuando como **gateway/NAT** e **firewall stateful**. Os testes com `curl`, `dig` e `ping` confirmaram o **bloqueio/permit** conforme regras, e os **logs** do pfSense registraram as ocorrências, reforçando os pilares de **Confidencialidade/Disponibilidade** e a importância de **ordenação e precisão das regras**.

---

## Anexos (inserir prints)

* **Figura 1 —** Topologia VirtualBox (WAN=NAT, LAN=`LAN_PFS`).
* **Figura 2 —** Regras do pfSense (LAN) com `BLOCK_LAN_HTTP_OUT` no topo.
* **Figura 3 —** Log de bloqueio HTTP (porta 80) em **Status > System Logs > Firewall**.
* **Figura 4 —** `dig` usando DNS do pfSense (sucesso) e `dig @8.8.8.8` (bloqueado).
* **Figura 5 —** `ping` ao gateway (ok) e a 8.8.8.8 (bloqueado).

---

## Apêndice — Troubleshooting rápido

* **Cliente sem IP na LAN:** confirme que a interface do Cliente está em **Internal Network `LAN_PFS`** e que o **DHCP da LAN** está **habilitado** no pfSense (Services > DHCP Server > LAN).
* **Sem acesso à WebGUI:** use `https://192.168.10.1` e aceite o certificado autoassinado; confira se a regra **LAN → any** não foi removida acidentalmente.
* **Regra não funciona:** lembre-se que o pfSense avalia **de cima para baixo**; coloque **blocks** acima das regras de *allow*.
* **Bloqueio de HTTP não aparece no log:** ative o **Log** na própria regra (ícone/log na linha da regra) e aplique.
* **`dig @8.8.8.8` ainda responde:** verifique se a regra de **Block DNS 53** está acima da allow geral; garanta que o **DNS Resolver** do pfSense está ligado na **LAN**.
* **`ping 8.8.8.8` ainda sai:** confira se a regra `ALLOW_ICMP_TO_GATEWAY` está **acima** da `BLOCK_LAN_ICMP_INTERNET` e que o **block** cobre **any** destino.
* **Cliente sem Internet:** verifique se a **WAN (pfSense)** obteve IP via **DHCP** (Status > Interfaces) e se o **NAT de saída** está em *Automatic outbound NAT* (padrão).
* **Conflitos de rede:** evite sobrepor a LAN (`192.168.10.0/24`) com a sub-rede do VirtualBox NAT (`10.0.2.0/24`).
