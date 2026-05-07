# T02 – Redes de Dados I

# Relatório 12: Configuração de Firewall de Rede usando **pfSense** (VMs no VirtualBox)

Este relatório descreve a configuração de um **firewall pfSense** atuando como **gateway/NAT e filtro** para uma rede interna com **duas VMs**: **pfSense** (gateway/firewall) e **user 2 - Debian** (cliente). O objetivo é **montar o ambiente**, aplicar **regras de firewall** típicas e **validar o comportamento** por meio de testes práticos e análise de **logs** no pfSense.

* **Material de apoio:** `https://github.com/vin1sss/T02---Redes-de-Dados-1/`

---

## I. Introdução

Você utilizará um **pfSense** com duas interfaces (WAN/LAN) no VirtualBox:

* **WAN**: acesso à Internet via **NAT** do VirtualBox.
* **LAN**: rede isolada (**Internal Network**) onde ficará a VM **user 2 - Debian**.

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
  * **Recursos da VM:** **6 GB de RAM** e **3 núcleos de CPU**
* **user 2 - Debian**

  * **Adapter 1:** **Internal Network** **`LAN_PFS`** (IP via **DHCP** do pfSense).
  * **Recursos da VM:** **6 GB de RAM** e **3 núcleos de CPU**

> **Assunção para o lab:** usar a **configuração padrão do pfSense** para LAN (ex.: `192.168.1.1/24` com DHCP habilitado). Não trataremos o “primeiro setup” do pfSense neste relatório.

> **Observação:** Diferente do Relatório 10 (NAT Network para ambas as VMs), aqui o pfSense **precisa de duas interfaces** (WAN e LAN). Por isso usamos **NAT** (WAN) + **Internal Network** (LAN).

---

## IV. Instalação e Preparação

### 0) **Configurando pfSense**

1. **pfSense — habilitar e configurar as duas interfaces no VirtualBox**

* VirtualBox → **botão direito** na VM **pfSense** → **Configurações** → **Rede**.
* **Adaptador 1 (WAN):**

  * **Habilitar Placa de Rede**
  * **Conectado a:** **NAT**
  * **Anotar o endereço MAC do adaptador** — os últimos 4 caracteres são suficientes para posterior configuração no pfSense.
  <img width="806" height="377" alt="image" src="https://github.com/user-attachments/assets/ed4886ae-aed5-4681-b021-6a73fbf13397" />

* **Adaptador 2 (LAN):**

  * **Habilitar Placa de Rede**
  * **Conectado a:** **Internal Network**
  * **Nome:** **`LAN_PFS`**  ← **digite exatamente este nome** (se não existir, o VirtualBox cria ao salvar).
  * **Anotar o endereço MAC do adaptador** — os últimos 4 caracteres são suficientes para posterior configuração no pfSense.
  <img width="800" height="375" alt="image" src="https://github.com/user-attachments/assets/ca317cf7-a5c4-4fff-b7b3-fd1f3e8ca574" />

* **OK**.

2. **user 2 - Debian — conectar à mesma LAN**

* **Botão direito** na VM **user 2 - Debian** → **Configurações** → **Rede**.
* **Adaptador 1:** **Internal Network** → **Nome:** **`LAN_PFS`**.
  <img width="802" height="334" alt="image" src="https://github.com/user-attachments/assets/f28dd00a-cc73-4b28-9f10-47232d2b9d10" />

* **OK**.

3. **Ligar o pfSense**

* Inicie a VM **pfSense** no VirtualBox e aguarde o carregamento completo.

#### A) Resetar configurações

No terminal do pfSense:

1. Selecione **`4) Reset to factory`**.
2. Confirme com **`y`**.

#### B) Associar interfaces de rede

Na tela de boas-vindas do pfSense, é possível verificar que existem duas interfaces: **em0** e **em1**.

<img width="800" alt="000 welcome com indicacao das duas interfaces existentes" src="https://github.com/user-attachments/assets/1417dec6-ddea-4bb7-b24f-99c60ae03e8a" />


1. Digite **`1`** e pressione **Enter** para selecionar **"Assign Interfaces"**.
2. Serão exibidas as interfaces disponíveis (**em0** e **em1**) com seus respectivos **endereços MAC**.
3. Compare os endereços MAC exibidos com os anotados nas configurações do VirtualBox:

   * Para **WAN**, selecione a interface cujo MAC corresponde ao adaptador do tipo **NAT**.
   * Para **LAN**, selecione a interface cujo MAC corresponde ao adaptador **Internal Network** (`LAN_PFS`).

4. Quando perguntado **"Do you want to proceed?"**, digite **`y`** e pressione **Enter**.

<img width="800" alt="001 associacao de interfaces no pfsense" src="https://github.com/user-attachments/assets/a8dd0bcc-f28d-4292-a8a2-969345070ee7" />

5. Aguarde a conclusão. Na tela de boas-vindas, a associação estará atualizada — no teste realizado: **em0 → WAN** e **em1 → LAN**.

#### C) Definir endereço IP da interface WAN

Como o adaptador WAN é do tipo **NAT**, o VirtualBox fornece endereço IP automaticamente via DHCP; portanto, a interface será configurada dessa forma.

1. Digite **`2`** e pressione **Enter** para selecionar **"Set interface(s) IP addresses"**.
2. Selecione o número correspondente à **WAN** (no teste realizado: **`1`**) e pressione **Enter**.
3. **"Configure IPv4 address WAN interface via DHCP?"** → Digite **`y`** e pressione **Enter**.
4. **"Configure IPv6 address WAN interface via DHCP6?"** → Digite **`n`** e pressione **Enter**.
5. Pressione **Enter**.
6. **"Do you want to revert to HTTP as the webConfigurator protocol?"** → Digite **`n`** e pressione **Enter**.

<img width="800" alt="002 atribuindo DHCP para interface WAN" src="https://github.com/user-attachments/assets/47148e09-163d-4138-9e53-c1bfd7607010" />

7. Quando solicitado, pressione **Enter** para retornar ao menu principal.

Após a conclusão, na tela de boas-vindas a linha **WAN** deverá indicar **v4/DHCP** e um endereço IP condizente com a rede NAT do VirtualBox (ex.: `10.0.2.x`).

#### D) Definir endereço estático da interface LAN e configurar DHCP da rede

Como a **Rede Interna** não possui nenhum serviço DHCP por parte do VirtualBox, o pfSense será responsável por fornecer endereços IP às máquinas conectadas a essa rede.

1. Digite **`2`** e pressione **Enter** para selecionar **"Set interface(s) IP addresses"**.
2. Selecione o número correspondente à **LAN** (no teste realizado: **`2`**) e pressione **Enter**.
3. **"Configure IPv4 address LAN interface via DHCP?"** → Digite **`n`** e pressione **Enter**.
4. Digite o endereço IP **`192.168.1.1`** e pressione **Enter**.
5. Digite a máscara de sub-rede **`24`** e pressione **Enter**.
6. Pressione **Enter** (sem digitar nada) para o campo de upstream gateway.

<img width="800" alt="003 atribuindo ip estático para interface LAN" src="https://github.com/user-attachments/assets/ee63ff00-d73b-44ee-a4f8-70c42eccbb8c" />

7. **"Configure IPv6 address LAN interface via DHCP6?"** → Digite **`n`** e pressione **Enter**.
8. Pressione **Enter** (sem digitar nada) para o campo de endereço IPv6.
9. **"Do you want to enable the DHCP server on LAN?"** → Digite **`y`** e pressione **Enter**.
10. **"Enter the start address of the IPv4 client address range:"** → Digite **`192.168.1.10`** e pressione **Enter**.
11. **"Enter the end address of the IPv4 client address range:"** → Digite **`192.168.1.254`** e pressione **Enter**.

<img width="800" alt="004 ativando servidor DHCP para interface LAN" src="https://github.com/user-attachments/assets/a87843d7-7493-49e1-9fd4-c617b98efccc" />

12. **"Do you want to revert to HTTP as the webConfigurator protocol?"** → Digite **`n`** e pressione **Enter**.

Quando solicitado que se pressione **Enter**, surgirá a mensagem **"You can access the webConfigurator by opening the following URL in your browser"**, confirmando que o IP foi corretamente configurado. O endereço estático da interface LAN (**`192.168.1.1`**) também será exibido — máquinas conectadas à Rede Interna já podem acessar o pfSense por esse endereço.

#### E) user 2 - Debian — conectar à Rede Interna

Inicie a VM **user 2 - Debian** e aguarde a obtenção de endereço IP via DHCP do pfSense.

Instale utilitários (se necessário) e verifique a conectividade:

```bash
sudo apt update && sudo apt install -y net-tools dnsutils curl
ip a                 # deve obter IP na sub-rede da LAN (ex.: 192.168.1.x)
ip route
ping -c2 192.168.1.1 # gateway do pfSense
```

* **Se o `user 2 - Debian` estava com IP estático, resetar para DHCP:**

  ```bash
  IFACE=$(ip route | awk '/default/ {print $5; exit}')
  sudo dhclient -r "$IFACE" || true
  sudo ip addr flush dev "$IFACE"
  sudo dhclient "$IFACE"
  ip -4 a show "$IFACE"
  ```

> **Acesso à WebGUI do pfSense (para criar regras e ver logs):** no navegador do user 2 - Debian, abra `https://192.168.1.1` (ou o IP LAN do pfSense) e aceite o certificado autoassinado.

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

2. **Teste (user 2 - Debian):**

```bash
curl -v http://example.com        # deve FALHAR (bloqueado)
curl -v https://example.com       # deve OK
```

* Você pode testar acessando os sites **diretamente no navegador** também.

3. **Logs (pfSense):** **Status > System Logs > Firewall**, filtre por **Interface = LAN** e **porta 80**.
   Verifique entradas **blocked** oriundas do IP do user 2 - Debian.

---

### Cenário 2 — Bloquear **um site específico** (por FQDN/alias)

**Objetivo:** impedir acesso a um domínio específico (ex.: `www.wikipedia.org`) mantendo o restante da navegação liberado.

> **Como funciona:** no pfSense, um **Alias** do tipo **Host(s)** aceita **FQDN (Fully Qualified Domain Name)**. O pfSense resolve esse nome para IP(s) e a **regra de bloqueio** usa esse alias como **destino**.
> *Obs.: em sites atrás de CDNs os IPs podem mudar; para fins de laboratório, o método é suficiente.*
> *Obs. 2: a atualização do alias por FQDN pode levar alguns minutos; em sala, aguarde um curto intervalo antes de repetir o teste.*

1. **Criar o Alias (pfSense WebGUI) — Firewall > Aliases > Add**

* **Name:** `BLOCK_WIKI`
* **Type:** *Host(s)*
* **Host(s):** `www.wikipedia.org`
* **Description:** `FQDN do site a bloquear`
* **Save** → **Apply Changes**

2. **Criar a regra de bloqueio (pfSense) — Firewall > Rules > LAN → Add (seta para cima)**

* **Action:** *Block*
* **Interface:** *LAN*
* **Address Family:** *IPv4*
* **Protocol:** *TCP*
* **Source:** *LAN net*
* **Destination:** **`BLOCK_WIKI`** (o alias criado)
* **Destination Port Range:** *any*
* **Description:** `BLOCK_SITE_WIKIPEDIA`
* **Save** → **Apply Changes**

> **Importante:** mantenha esta regra **acima** da regra “allow LAN to any”.

3. **Teste (user 2 - Debian) — navegador**

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

2. **Adicionar exceção para o gateway (opcional, acima do block):**

* **Action:** *Pass*
* **Protocol:** *ICMP*
* **Source:** *LAN net*
* **Destination:** *Address or alias* → **192.168.1.1**
* **Description:** `ALLOW_ICMP_TO_GATEWAY`
* **Save** → **Apply Changes**

3. **Teste (user 2 - Debian):**

```bash
ping -c 2 8.8.8.8          # deve FALHAR
ping -c 2 192.168.1.1     # deve OK
```

4. **Logs:** ver **blocks** ICMP na saída.

---

## VI. Verificação e Resultados

### 1) Quadro comparativo (cenários)

| Cenário | Tráfego                                                    | Regra aplicada            | Resultado esperado | Validação (user 2 - Debian)                                                           |
| :-----: | ---------------------------------------------------------- | ------------------------- | ------------------ | ----------------------------------------------------------------------------- |
|    1    | HTTP 80 (saída, geral)                                     | `BLOCK_LAN_HTTP_OUT`      | **Bloqueado**      | Navegador: **[http://neverssl.com](http://neverssl.com)** (falha)             |
|    1    | HTTPS 443 (saída, geral)                                   | Allow padrão              | **Permitido**      | Navegador: **[https://example.com](https://example.com)** (ok)                |
|    2    | HTTPS p/ **[www.wikipedia.org](https://www.wikipedia.org)** | `BLOCK_SITE_WIKIPEDIA`    | **Bloqueado**      | Navegador: **[https://www.wikipedia.org](https://www.wikipedia.org)** (falha) |
|    2    | HTTPS p/ outros destinos                                   | Allow padrão              | **Permitido**      | Navegador: **[https://example.com](https://example.com)** (ok)                |
|    3    | ICMP Internet                                              | `BLOCK_LAN_ICMP_INTERNET` | **Bloqueado**      | `ping 8.8.8.8` (falha)                                                        |
|    3    | ICMP → gateway da LAN                                      | `ALLOW_ICMP_TO_GATEWAY`   | **Permitido**      | `ping 192.168.1.1` (ok)                                                       |

### 2) Onde analisar

* **pfSense → Status > System Logs > Firewall** (filtro **Interface = LAN**).
* Correlacione **timestamp** dos testes com registros **pass/block**.

### 3) Critérios de sucesso do experimento (guia)

* **Cenário 1:** HTTP (80) bloqueado e HTTPS permitido a partir do user 2 - Debian.
* **Cenário 2:** `www.wikipedia.org` bloqueado via alias, com outros sites liberados.
* **Cenário 3:** ICMP para Internet bloqueado e ICMP para gateway permitido (quando a exceção for aplicada acima da regra de bloqueio).

---

## VII. Conclusão

Demonstrou-se, com **duas VMs** (pfSense e user 2 - Debian), que o **pfSense** aplica **políticas de saída** eficazes (HTTP geral, **site específico**, ICMP), atuando como **gateway/NAT** e **firewall stateful**. Testes no **navegador** e com **ping** confirmaram os resultados, e os **logs** evidenciaram os eventos, reforçando a importância da **ordem das regras** e do **monitoramento**.

---

## Apêndice — Troubleshooting rápido

* **user 2 - Debian sem IP na LAN:** confirme **Internal Network `LAN_PFS`** no adaptador e que o **DHCP da LAN** do pfSense está ativo.
* **Sem acesso à WebGUI:** use `https://192.168.1.1` (ou IP LAN do pfSense) e aceite o certificado; verifique se a regra **allow LAN to any** não foi removida.
* **Regra não surte efeito:** lembre-se da avaliação **top-down**; mantenha **blocks acima** do allow geral; habilite **Log** na regra.
* **Site específico ainda abre:** confirme a **ordem** da regra, o **alias** (`BLOCK_WIKI` → `www.wikipedia.org`), limpe o **cache DNS** do cliente e aguarde a **atualização do alias** pelo pfSense.
* **`http://neverssl.com` abre mesmo bloqueado:** verifique se a regra de **porta 80** está no **topo** e se não há regra conflitante; confira os **logs** do pfSense.
* **`ping 8.8.8.8` ainda sai:** confirme a regra **Block ICMP** e que a exceção **ALLOW_ICMP_TO_GATEWAY** está **acima** dela.
* **Sem Internet no user 2 - Debian:** verifique se a **WAN** do pfSense obteve IP via **DHCP** (Status > Interfaces) e se o **NAT de saída** está em *Automatic* (padrão).
* **Conflitos de rede:** evite sobrepor a LAN (`192.168.1.0/24`) com a sub-rede do NAT do VirtualBox (`10.0.2.0/24`).
