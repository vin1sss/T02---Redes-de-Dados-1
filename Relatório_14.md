# T02 – Redes de Dados I

# Relatório 14: Configuração de Firewall de Rede usando **pfSense** (VMs no VirtualBox)

Este relatório descreve a configuração de um **firewall pfSense** atuando como **gateway/NAT e filtro** para uma rede interna com **duas VMs**: **Cliente (Debian Desktop)** e **pfSense**. O objetivo é **montar o ambiente**, aplicar **regras de firewall** típicas e **validar o comportamento** por meio de testes práticos e análise de **logs** no pfSense.

* **Material de apoio:** ```https://github.com/vin1sss/T02---Redes-de-Dados-1/```

---

## I. Introdução

Você utilizará um **pfSense** com duas interfaces (WAN/LAN) no VirtualBox:

* **WAN**: acesso à Internet via **NAT** do VirtualBox.
* **LAN**: rede isolada (**Internal Network**) onde ficará a VM **Cliente** (Debian).

Aplicaremos **regras** (ex.: **bloquear HTTP**, **bloquear um site específico**, **bloquear ICMP para Internet**) e verificaremos **logs** no pfSense.
**Pilares:** **Confidencialidade** e **Disponibilidade**, com ênfase em **Controle de Acesso** e **Auditoria**.

---

## II. Conceitos e Fundamentos

* **Firewall stateful (pfSense):** regras avaliadas **de cima para baixo**; mantém **estado** das conexões.
* **NAT:** traduz IPs da LAN privada para o IP da WAN (saída para Internet).
* **Ordem de regras:** a **primeira regra compatível** decide (ALLOW/DENY).
* **Logs:** registram eventos **permitidos/bloqueados**, essenciais para auditoria.
* **Testes práticos:** **navegador** (HTTP/HTTPS) e `ping` (ICMP).

---

## III. Ambiente e Topologia

**VirtualBox (2 VMs):**

* **VM-pfSense**

  * **Adapter 1 (WAN):** **NAT** (DHCP do VBox).
  * **Adapter 2 (LAN):** **Internal Network** chamada **`LAN_PFS`** (pfSense atende esta LAN).
* **VM-Cliente (Debian Desktop)**

  * **Adapter 1:** **Internal Network** **`LAN_PFS`** (IP via **DHCP** do pfSense).

> **Assunção para o lab:** usar a **configuração padrão do pfSense** para LAN (ex.: `192.168.1.1/24` com DHCP habilitado). Não trataremos o “primeiro setup” do pfSense neste relatório.

> **Observação:** Diferente do Relatório 13 (NAT Network para ambas as VMs), aqui o pfSense **precisa de duas interfaces** (WAN e LAN). Por isso usamos **NAT** (WAN) + **Internal Network** (LAN).

---

## IV. Instalação e Preparação

### 0) **Preparar as redes (criando pelas Configurações da VM)**

1. **pfSense — habilitar e configurar as duas interfaces**

* VirtualBox → **botão direito** na VM **pfSense** → **Configurações** → **Rede**.
* **Adaptador 1 (WAN):**

  * **Habilitar Placa de Rede** 
  * **Conectado a:** **NAT**
* **Adaptador 2 (LAN):**

  * **Habilitar Placa de Rede** 
  * **Conectado a:** **Internal Network**
  * **Nome:** **`LAN_PFS`**  ← **digite exatamente este nome** (se não existir, o VirtualBox cria ao salvar).
* **OK**.

2. **Cliente (Debian) — conectar à mesma LAN**

* **Botão direito** na VM **Cliente** → **Configurações** → **Rede**.
* **Adaptador 1:** **Internal Network** → **Nome:** **`LAN_PFS`**.
* **OK**.

3. **Inicialização e verificação rápida**

* Inicie **pfSense** e depois o **Cliente**.
* No **Cliente**:

  ```bash
  ip a                 # deve obter IP na sub-rede da LAN (ex.: 192.168.1.x)
  ping -c2 192.168.1.1 # (opcional) gateway do pfSense
  ```

### A) Cliente (Debian Desktop)

Instale utilitários (se necessário):

```bash
sudo apt update && sudo apt install -y net-tools dnsutils curl
ip route
```

> **Acesso à WebGUI do pfSense (para criar regras e ver logs):** no navegador do Cliente, abra `https://192.168.1.1` (ou o IP LAN do pfSense) e aceite o certificado autoassinado.

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

[![image.png](https://i.postimg.cc/cHKYv8pq/image.png)](https://postimg.cc/N9cLVLGb)

2. **Teste (Cliente):**

```bash
curl -v http://example.com        # deve FALHAR (bloqueado)
curl -v https://example.com       # deve OK
```

* Você pode testar acessando os sites **diretamente no navegador** também.

[![image.png](https://i.postimg.cc/N0K7HVT2/image.png)](https://postimg.cc/NywHhddQ)
[![image.png](https://i.postimg.cc/QMDh9LvM/image.png)](https://postimg.cc/5XsZTr4c)

3. **Logs (pfSense):** **Status > System Logs > Firewall**, filtre por **Interface = LAN** e **porta 80**.
   Verifique entradas **blocked** oriundas do IP do Cliente.

---

### Cenário 2 — Bloquear **um site específico** (por FQDN/alias)

**Objetivo:** impedir acesso a um domínio específico (ex.: `www.wikipedia.org`) mantendo o restante da navegação liberado.

> **Como funciona:** no pfSense, um **Alias** do tipo **Host(s)** aceita **FQDN(Fully Qualified Domain Name)**. O pfSense resolve esse nome para IP(s) e a **regra de bloqueio** usa esse alias como **destino**.
> *Obs.: em sites atrás de CDNs os IPs podem mudar; para fins de laboratório, o método é suficiente.*

1. **Criar o Alias (pfSense WebGUI) — Firewall > Aliases > Add**

* **Name:** `BLOCK_WIKI`
* **Type:** *Host(s)*
* **Host(s):** `www.wikipedia.org`
* **Description:** `FQDN do site a bloquear`
* **Save** → **Apply Changes**

2. **Criar a regra de bloqueio (pfSense) — Firewall > Rules > LAN → Add (seta para cima)**

* **Action:** *Block*
* **Interface:** *LAN*
* **Family:** *IPv4*
* **Protocol:** *TCP*
* **Source:** *LAN net*
* **Destination:** **`BLOCK_WIKI`** (o alias criado)
* **Destination Port Range:** *any*
* **Description:** `BLOCK_SITE_WIKIPEDIA`
* **Save** → **Apply Changes**

> **Importante:** mantenha esta regra **acima** da regra “allow LAN to any”.

[![image.png](https://i.postimg.cc/vHhhn54J/image.png)](https://postimg.cc/rKd5X0Cj)

3. **Teste (Cliente) — navegador**

* Abra **[https://www.wikipedia.org](https://www.wikipedia.org)** → **deve FALHAR** (bloqueado).
* Abra **[https://example.com](https://example.com)** → **deve abrir normalmente** (não bloqueado).

4. **Logs (pfSense):** **Status > System Logs > Firewall**, filtre por **Interface = LAN** e verifique entradas **blocked** cujo **Destination** é um dos IPs resolvidos para `www.wikipedia.org`.

> **Dica:** se o site ainda abrir, limpe cache DNS do cliente e aguarde a atualização do alias (o pfSense **resolve periodicamente** os FQDNs). Também confira a **ordem** da regra na aba **LAN**.

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

[![image.png](https://i.postimg.cc/c4tYxYQF/image.png)](https://postimg.cc/rKczgDZ4)

2. **Adicionar exceção para o gateway (opcional, acima do block):**

* **Action:** *Pass*
* **Protocol:** *ICMP*
* **Source:** *LAN net*
* **Destination:** *Address or alias* → **192.168.1.1**
* **Description:** `ALLOW_ICMP_TO_GATEWAY`
* **Save** → **Apply Changes**

[![image.png](https://i.postimg.cc/52MHfr95/image.png)](https://postimg.cc/TpC29CDh)

3. **Teste (Cliente):**

```bash
ping -c 2 8.8.8.8          # deve FALHAR
ping -c 2 192.168.1.1     # deve OK
```

[![image.png](https://i.postimg.cc/15bGwM9k/image.png)](https://postimg.cc/F7gkQykp)

4. **Logs:** ver **blocks** ICMP na saída.

---

## VI. Verificação e Resultados

### 1) Quadro comparativo (cenários)

| Cenário | Tráfego                                                    | Regra aplicada            | Resultado esperado | Validação (Cliente)                                                           |
| :-----: | ---------------------------------------------------------- | ------------------------- | ------------------ | ----------------------------------------------------------------------------- |
|    1    | HTTP 80 (saída, geral)                                     | `BLOCK_LAN_HTTP_OUT`      | **Bloqueado**      | Navegador: **[http://neverssl.com](http://neverssl.com)** (falha)             |
|    1    | HTTPS 443 (saída, geral)                                   | Allow padrão              | **Permitido**      | Navegador: **[https://example.com](https://example.com)** (ok)                |
|    2    | HTTPS p/ **[www.wikipedia.org](http://www.wikipedia.org)** | `BLOCK_SITE_WIKIPEDIA`    | **Bloqueado**      | Navegador: **[https://www.wikipedia.org](https://www.wikipedia.org)** (falha) |
|    2    | HTTPS p/ outros destinos                                   | Allow padrão              | **Permitido**      | Navegador: **[https://example.com](https://example.com)** (ok)                |
|    3    | ICMP Internet                                              | `BLOCK_LAN_ICMP_INTERNET` | **Bloqueado**      | `ping 8.8.8.8` (falha)                                                        |
|    3    | ICMP → gateway da LAN                                      | `ALLOW_ICMP_TO_GATEWAY`   | **Permitido**      | `ping 192.168.1.1` (ok)                                                       |

### 2) Onde analisar

* **pfSense → Status > System Logs > Firewall** (filtro **Interface = LAN**).
* Correlacione **timestamp** dos testes com registros **pass/block**.

---

## VII. Conclusão

Demonstrou-se, com **duas VMs** (pfSense e Cliente), que o **pfSense** aplica **políticas de saída** eficazes (HTTP geral, **site específico**, ICMP), atuando como **gateway/NAT** e **firewall stateful**. Testes no **navegador** e com **ping** confirmaram os resultados, e os **logs** evidenciaram os eventos, reforçando a importância da **ordem das regras** e do **monitoramento**.

---

## Apêndice — Troubleshooting rápido

* **Cliente sem IP na LAN:** confirme **Internal Network `LAN_PFS`** no adaptador e que o **DHCP da LAN** do pfSense está ativo.
* **Sem acesso à WebGUI:** use `https://192.168.1.1` (ou IP LAN do pfSense) e aceite o certificado; verifique se a regra **allow LAN to any** não foi removida.
* **Regra não surte efeito:** lembre-se da avaliação **top-down**; mantenha **blocks acima** do allow geral; habilite **Log** na regra.
* **Site específico ainda abre:** confirme a **ordem** da regra, o **alias** (`BLOCK_WIKI` → `www.wikipedia.org`), limpe o **cache DNS** do cliente e aguarde a **atualização do alias** pelo pfSense.
* **`http://neverssl.com` abre mesmo bloqueado:** verifique se a regra de **porta 80** está no **topo** e se não há regra conflitante; confira os **logs** do pfSense.
* **`ping 8.8.8.8` ainda sai:** confirme a regra **Block ICMP** e que a exceção **ALLOW_ICMP_TO_GATEWAY** está **acima** dela.
* **Sem Internet no Cliente:** verifique se a **WAN** do pfSense obteve IP via **DHCP** (Status > Interfaces) e se o **NAT de saída** está em *Automatic* (padrão).
* **Conflitos de rede:** evite sobrepor a LAN (`192.168.1.0/24`) com a sub-rede do NAT do VirtualBox (`10.0.2.0/24`).
