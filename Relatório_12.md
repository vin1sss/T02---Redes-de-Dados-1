<img width="180" alt="image" src="https://github.com/user-attachments/assets/cf68b22b-ecb8-4e9e-8f09-271ef1bc1246" />

<div align="right">
T02 - Redes de Dados
</div>

# Relatório 12: Configuração de Firewall de Rede usando **pfSense** (VMs no VirtualBox)

Este relatório descreve a configuração de um **firewall pfSense** atuando como **gateway/NAT e filtro** para uma rede interna com **duas VMs**: **pfSense** (gateway/firewall) e **Debian** (cliente). O objetivo é **montar o ambiente**, aplicar **regras de firewall** típicas e **validar o comportamento** por meio de testes práticos e análise de **logs** no pfSense.

* **Material de apoio:** `https://github.com/vin1sss/T02---Redes-de-Dados-1/`

---

## I. Introdução

Você utilizará um **pfSense** com duas interfaces (WAN/LAN) no VirtualBox:

* **WAN**: acesso à Internet via **NAT** do VirtualBox.
* **LAN**: rede isolada (**Rede Interna**) onde ficará a VM **Debian**.

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
  * **Adapter 2 (LAN):** **Rede Interna** chamada **`LAN_PFS`** (pfSense atende esta LAN).
  * **Recursos da VM:** **6 GB de RAM** e **3 núcleos de CPU**
* **Debian**

  * **Adapter 1:** **Rede Interna** **`LAN_PFS`** (IP via **DHCP** do pfSense).
  * **Recursos da VM:** **6 GB de RAM** e **3 núcleos de CPU**

> **Assunção para o lab:** usar a **configuração padrão do pfSense** para LAN (ex.: `192.168.1.1/24` com DHCP habilitado). Não trataremos o “primeiro setup” do pfSense neste relatório.

> **Observação:** Diferente do Relatório 10 (NAT Network para ambas as VMs), aqui o pfSense **precisa de duas interfaces** (WAN e LAN). Por isso usamos **NAT** (WAN) + **Rede Interna** (LAN).

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
  * **Conectado a:** **Rede Interna**
  * **Nome:** **`LAN_PFS`**  ← **digite exatamente este nome** (se não existir, o VirtualBox cria ao salvar).
  * **Anotar o endereço MAC do adaptador** — os últimos 4 caracteres são suficientes para posterior configuração no pfSense.
  <img width="800" height="375" alt="image" src="https://github.com/user-attachments/assets/ca317cf7-a5c4-4fff-b7b3-fd1f3e8ca574" />

* **OK**.

2. **Debian — conectar à mesma LAN**

* **Botão direito** na VM **Debian** → **Configurações** → **Rede**.
* **Adaptador 1:** **Rede Interna** → **Nome:** **`LAN_PFS`**.
  <img width="802" height="334" alt="image" src="https://github.com/user-attachments/assets/f28dd00a-cc73-4b28-9f10-47232d2b9d10" />

* **OK**.

3. **Ligar o pfSense**

* Inicie a VM **pfSense** no VirtualBox e aguarde o carregamento completo.

4. **OBSERVAÇÕES**
* No menu superior **"Visualisar" > "Tela virtual 1" > "Escalonar para 200%"**. Isso facilita a visualização no terminal.
* Se, em qualquer momento acabar pressionando "Ctrl+C", saindo da inferface CLI do `pfSense`, é possível retornar executando o binário: `/etc/rc.initial`.

#### A) Resetar configurações

No terminal do pfSense:

1. Selecionar a opção **`4) Reset to factory`**: -> Digite 4. Pressione Enter.
2. Confirme digitando **`y`** e pressionando Enter.

#### B) Associar interfaces de rede

Na tela de boas-vindas do pfSense, é possível verificar que existem duas interfaces: **em0** e **em1**.

<img width="800" alt="000 welcome com indicacao das duas interfaces existentes" src="https://github.com/user-attachments/assets/1417dec6-ddea-4bb7-b24f-99c60ae03e8a" />


1. Digite **`1`** e pressione **Enter** para selecionar **"Assign Interfaces"**.
2. Quando perguntado **"Should VLAN be set up now?**, digite **`n`** e pressione **Enter**.
3. Serão exibidas as interfaces disponíveis (**em0** e **em1**) com seus respectivos **endereços MAC**.
4. Compare os endereços MAC exibidos com os anotados nas configurações do VirtualBox:

   * Para **WAN**, selecione a interface cujo MAC corresponde ao adaptador do tipo **NAT**.
   * Para **LAN**, selecione a interface cujo MAC corresponde ao adaptador **Rede Interna** (`LAN_PFS`).

5. Quando perguntado **"Do you want to proceed?"**, digite **`y`** e pressione **Enter**.

<img width="800" alt="001 associacao de interfaces no pfsense" src="https://github.com/user-attachments/assets/a8dd0bcc-f28d-4292-a8a2-969345070ee7" />

6. Aguarde a conclusão. Na tela de boas-vindas, a associação estará atualizada — no teste realizado: **em0 → WAN** e **em1 → LAN**.

#### C) Definir endereço IP da interface WAN

Como o adaptador WAN é do tipo **NAT**, o VirtualBox fornece endereço IP automaticamente via DHCP; portanto, a interface será configurada dessa forma.

1. Digite **`2`** e pressione **Enter** para selecionar **"Set interface(s) IP addresses"**.
2. Selecione o número correspondente à **WAN** (no teste realizado: **`1`**) e pressione **Enter**.
3. **"Configure IPv4 address WAN interface via DHCP?"** → Digite **`y`** e pressione **Enter**.
4. **"Configure IPv6 address WAN interface via DHCP6?"** → Digite **`n`** e pressione **Enter**.
5. Pressione **Enter** (para que o endereço IPv6 não seja configurado).
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

#### E) Debian — conectar à Rede Interna

Inicie a VM **Debian** e aguarde a obtenção de endereço IP via DHCP do pfSense.
   
1. Configuração do NetworkManager (Recomendado):
   * **Limpe o arquivo de interfaces:**
   Remova qualquer configuração de interface física (ex: `eth0`, `enp...`) do arquivo `/etc/network/interfaces`. Deixe apenas o loopback para evitar conflitos:
   ```bash
   # Deixe apenas isso:
   auto lo
   iface lo inet loopback
   ```
   * **Verifique o NetworkManager:**
   * Certifique-se de que o serviço está rodando:
   ```bash
   systemctl status NetworkManager
   ```
   * **Configure o Perfil:**
   Em vez de comandos isolados, use a interface das **Configurações do sistema** (Gnome/KDE) para editar o perfil da rede ou criar um novo.
      * Vá em **Configurações > Rede**.
      * Clique na engrenagem da sua conexão.
      * Em **IPv4**, garanta que esteja em **Automático (DHCP)**.
   * **Reinicie para aplicar:**
   ```bash
   sudo systemctl restart NetworkManager
   ```
   
2. Verifique a conectividade:
   ```bash
   ip a           # deve obter IP na sub-rede da LAN
   ip route       # verifique se o gateway padrão aponta para o pfSense
   ping -c2 8.8.8.8
   ```
   
3. Instale utilitários: 
   ```bash
   sudo apt update && sudo apt install -y net-tools dnsutils curl
   ```
   **Importante:** Os comandos `sudo apt update` e `sudo apt install` necessitam de acesso a Internet.

4. **Acesso à WebGUI do pfSense (para criar regras e ver logs):** no navegador do Debian, abra `https://192.168.1.1` (ou o IP LAN do pfSense) e aceite o certificado autoassinado.
5. Aqui, ignorar aviso de segurança para certificado (do pfSense) ausente. Selecione "Advanced..." e "Accept the Risk and Continue".
   <img width="800" alt="image" src="https://github.com/user-attachments/assets/93f8d318-91b0-4530-a728-449236d65ab5" />
6. Credenciais de acesso da interface web: usuário:"admin" e senha:"pfsense".

---

## V. Procedimentos (Passo a Passo)

> [!IMPORTANT]  
> No pfSense, vá em **Firewall > Rules > LAN**. As regras são lidas **de cima para baixo**. Coloque as **regras de bloqueio acima** da regra “allow LAN to any”.

### Cenário 1 — Bloquear **HTTP (porta 80)** e permitir **HTTPS**

**Objetivo:** impedir navegação HTTP (em texto claro), mantendo a versão com criptografia (HTTPS) funcional.

1. **pfSense (WebGUI):** Na interface web, abra a página Firewall > Rules > LAN, e clique em `Add (seta para cima)`
   <img width="800" alt="000 cenario 1 interface web abrindo pagina rules" src="https://github.com/user-attachments/assets/f697d5ae-16d7-4d85-977e-95004caaaff4" />
2. Defina os parâmetro de necessários, listados abaixo:
   * **Action:** *Block*
   * **Interface:** *LAN*
   * **Address Family:** *IPv4*
   * **Protocol:** *TCP*
   * **Source:** *LAN subnets*
   * **Destination:** *any*
   * **Destination Port Range:** `HTTP (80)`
   * **Log:** (marcar opção)
   * **Description:** `BLOCK_LAN_HTTP_OUT`
   * **Save** → **Apply Changes**
#### Validação 1 (terminal Debian):
1. Execute o comando abaixo, na tentativa de acessar o domínio `example.com`. Ele deverá falhar, pois a requisição está sendo feita com o protocolo bloqueado (HTTP).
   ```bash
   curl -v -m4 http://example.com
   ```
   <img width="800" alt="001 cenario1 validacao1 falha ao requisitar HTTP" src="https://github.com/user-attachments/assets/e62fcfa9-7746-464c-a0ec-03b11057337e" />

2. Em seguida, altere o comando, substituindo `http` por `https`, e execute-o. A requisição deve retornar o código de resposta `200 OK`.
   <img width="800" alt="002 cenario1 validacao2 sucesso ao requisitar HTTPS" src="https://github.com/user-attachments/assets/409fb7f4-176d-4389-918e-a2290bbd6c9d" />

  
#### **Validação 2 (Página Logs):**
Aqui iremos validar o bloqueio realizado por meio da interface web do pfSense:

1. Abra a página **Status > System Logs > Firewall**
2. Selecione os filtros para interface (`LAN`), porta de destino (`80`).
3. Verifique entradas **blocked** oriundas do IP do Debian.
   <img width="800" alt="003 cenario1 aplicando filtros na pagina Logs" src="https://github.com/user-attachments/assets/f3294c68-a7ce-421f-a93c-ddf7095b6351" />

---

### Cenário 2 — Bloquear **um site específico** (por FQDN/alias)

**Objetivo:** impedir acesso a um domínio específico (ex.: `www.wikipedia.org`) mantendo o restante da navegação liberado.

> **Como funciona:** no pfSense, um **Alias** do tipo **Host(s)** aceita **FQDN (Fully Qualified Domain Name)**. O pfSense resolve esse nome para IP(s) e a **regra de bloqueio** usa esse alias como **destino**.
> *Obs.: em sites atrás de CDNs os IPs podem mudar; para fins de laboratório, o método é suficiente.*
> *Obs. 2: a atualização do alias por FQDN pode levar alguns minutos; em sala, aguarde um curto intervalo antes de repetir o teste.*

1. **Criar o Alias (pfSense WebGUI) — Firewall > Aliases > Add**
Em "Properties":
* **Name:** `BLOCK_WIKI`
* **Type:** *Host(s)*
Em "Host(s)":
* **IP or FQDN:** `www.wikipedia.org`
* **Description:** `FQDN do site a bloquear`
* **Save** → **Apply Changes**

2. **Criar a regra de bloqueio (pfSense) — Firewall > Rules > LAN → Add (seta para cima)**

* **Action:** *Block*
* **Interface:** *LAN*
* **Address Family:** *IPv4*
* **Protocol:** *TCP*
* **Source:** *LAN subnets*
* **Destination:** (Address or Alias), e o alias criado: **`BLOCK_WIKI`**
* **Destination Port Range:** *any*
* **Description:** `BLOCK_SITE_WIKIPEDIA`
* **Log:** (marcar opção)
* **Save** → **Apply Changes**

> [!IMPORTANT]  
> Mantenha esta regra **acima** da regra “allow LAN to any”.

#### **Validação 1 (Debian, navegador):**

1. Abra **[https://www.wikipedia.org](https://www.wikipedia.org)** → **deve FALHAR** (bloqueado).

2. Abra **[https://example.com](https://example.com)** → **deve abrir normalmente** (não bloqueado).

#### **Validação 2 (Página Logs):**
1. Abra a página **Status > System Logs > Firewall**
2. Selecione os filtros para interface (`LAN`).
3. Verifique entradas **blocked** cujo **Destination** é um dos IPs resolvidos para `www.wikipedia.org`.
   <img width="800"  alt="004 cenario 2 block wiki" src="https://github.com/user-attachments/assets/877268a9-d1a6-4ca5-b764-81563bcbff0f" />


> **Dica:** se o site ainda abrir, abra em uma nova guia. Também é possível limpar o cache e recarregar a página.

> [!IMPORTANT]  
> Confira a **ordem** da regra na aba **LAN**.

---

### Cenário 3 — Bloquear **ICMP para Internet**, permitir ICMP para o gateway

**Objetivo:** impedir `ping` para Internet (ex.: 8.8.8.8), mantendo o diagnóstico interno para o gateway.

1. Abra a página **pfSense → Firewall > Rules > LAN → Add (seta para cima):**
2. Configure a nova regra de acordo:
   * **Action:** *Block*
   * **Protocol:** *ICMP*
   * **ICMP subtypes:** *any*
   * **Source:** *LAN subnets*
   * **Destination:** *WAN subnets*
   * **Log:** (marcar opção)
   * **Description:** `BLOCK_LAN_ICMP_INTERNET`
   * **Save** -> **Apply Changes**

#### **Validação 1 (Debian, terminal):**

1. Acesse o terminal do Debian e digite ambos comandos abaixo. O primeiro deverá falhar, por tentar acessar um IP externo. Já o segundo, deverá ter sucesso, acessando o IP local (do próprio Gateway).
```bash
ping -c2 8.8.8.8
ping -c2 192.168.1.1
```
<img width="800" alt="005 cenario 3 validacao 1" src="https://github.com/user-attachments/assets/f46059ea-90a7-4867-b7da-bdffbb36cb54" />

#### **Validação 2 (Página Logs):**
1. Abra a página **Status > System Logs > Firewall**
2. Selecione os filtros para interface (`LAN`) e Destination Address (`8.8.8.8`).
4. Verifique entradas **blocked** cujo **Destination Addres** pertencem ao IP bloqueado.
   <img width="800" alt="006 cenario 3 validacao 2" src="https://github.com/user-attachments/assets/2df7f385-9cf2-45a4-a132-6c8298b0d82c" />


3. **Logs:** ver **blocks** ICMP na saída.

---

## VI. Conclusão

Demonstrou-se, com **duas VMs** (pfSense e Debian), que o **pfSense** aplica **políticas de saída** eficazes (HTTP geral, **site específico**, ICMP), atuando como **gateway/NAT** e **firewall stateful**. Testes no **navegador** e com **ping** confirmaram os resultados, e os **logs** evidenciaram os eventos, reforçando a importância da **ordem das regras** e do **monitoramento**.

---

## Apêndice — Troubleshooting rápido

* **Debian sem IP na LAN:** confirme **Rede Interna `LAN_PFS`** no adaptador e que o **DHCP da LAN** do pfSense está ativo.
* **Sem acesso à WebGUI:** use `https://192.168.1.1` (ou IP LAN do pfSense) e aceite o certificado; verifique se a regra **allow LAN to any** não foi removida.
* **Regra não surte efeito:** lembre-se da avaliação **top-down**; mantenha **blocks acima** do allow geral; habilite **Log** na regra.
* **Site específico ainda abre:** confirme a **ordem** da regra, o **alias** (`BLOCK_WIKI` → `www.wikipedia.org`), limpe o **cache DNS** do cliente e aguarde a **atualização do alias** pelo pfSense.
* **`http://neverssl.com` abre mesmo bloqueado:** verifique se a regra de **porta 80** está no **topo** e se não há regra conflitante; confira os **logs** do pfSense.
* **`ping 8.8.8.8` ainda sai:** confirme a regra **Block ICMP** e que a exceção **ALLOW_ICMP_TO_GATEWAY** está **acima** dela.
