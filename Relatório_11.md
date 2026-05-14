<img width="180" alt="image" src="https://github.com/user-attachments/assets/cf68b22b-ecb8-4e9e-8f09-271ef1bc1246" />

<div align="right">
T02 - Redes de Dados
</div>

# Relatório 11: Configuração de **IDS** de Rede usando **Suricata no Debian** (VM no VirtualBox)
 
Este relatório descreve a configuração de um **IDS** com **Suricata** **diretamente no Debian (uma única VM)**, monitorando o tráfego da própria VM para a **Internet**. Usaremos **apenas regras locais (Custom Rules)**, sem baixar rulesets externos. O objetivo é **instalar**, **iniciar** o Suricata em **modo IDS**, **gerar tráfego didático** (via navegador/`curl`) e **analisar os alertas** no `fast.log`/`eve.json`.

* **Material de apoio:** `https://github.com/vin1sss/T02---Redes-de-Dados-1/`

---

## I. Introdução

A única VM (Debian Desktop) atuará como **sensor IDS** (Suricata) e como **cliente** que gera tráfego. As regras locais foram desenhadas para disparar alertas de forma controlada e didática (URI, BODY/POST, HEADER e DNS).

Um IDS de rede opera de forma passiva: observa os pacotes, aplica assinaturas/regras de inspeção e gera alertas quando encontra padrões suspeitos, sem bloquear diretamente o tráfego. No Suricata, essa detecção ocorre com inspeção profunda de protocolos (DPI), permitindo visibilidade de elementos como URI, cabeçalhos, corpo HTTP e consultas DNS.

**Pilares:** **Confidencialidade** e **Monitoramento/Detecção**, com ênfase em **auditoria** e **visibilidade** do tráfego.

---

## II. Conceitos e Fundamentos

* **Firewall × IDS:** firewall **impõe** política (permite/bloqueia); IDS **observa e alerta** (passivo).
* **Suricata (DPI):** inspeção por **regras/assinaturas**. Vamos criar **regras locais** para comprovar a capacidade de inspeção de **URI**, **cabeçalhos**, **corpo HTTP** e **consultas DNS**.
* **HTTPS vs. HTTP:** em **HTTPS** o conteúdo é cifrado (IDS vê metadados, p.ex. SNI/JA3); em **HTTP** o IDS consegue inspecionar cabeçalhos e corpo.
* **Termos das regras (resumo):**

  * `flow:to_server` = tráfego **do cliente para o servidor** (requisição).
  * `http.uri` = caminho solicitado (p.ex. `/rota`).
  * `http_header` = cabeçalhos HTTP (ex.: `User-Agent`, `Host`, cabeçalhos customizados).
  * `http.request_body` = corpo enviado pelo cliente (POST/PUT).
  * `dns.query` = nome de domínio consultado no DNS.
  * `classtype`/`priority` = **classificação** e **prioridade** do alerta no log.

---

## III. Ambiente e Topologia

**Topologia lógica (1 VM):**

* **user 1 - Debian (com Suricata)** atuando como sensor IDS e cliente de teste.
* Saída para Internet através de NAT.

> **Topologia:** **user 1 - Debian ↔ NAT (VBox) ↔ Internet**.

### 1) Resumo do laboratório

| Elemento | Definição |
| --- | --- |
| Rede do VirtualBox | **NAT** com DHCP do VirtualBox |
| VM do laboratório | **user 1 - Debian** |
| Papel da VM | Sensor IDS com **Suricata** e cliente que gera o tráfego |
| Tráfego observado | Saída da própria VM para a Internet |
| Evidências principais | Alertas em `fast.log` e eventos em `eve.json` |
| Recursos da VM | **6 GB de RAM** e **3 núcleos de CPU** |

### 2) Referências usadas durante a execução

| Item | Uso |
| --- | --- |
| Senha das máquinas virtuais | **`pytest`** |
| Senha solicitada pelo `sudo` | **`pytest`** |
| Interface de saída da VM | Confirmada com `ip route get 1.1.1.1` |
| `enp0s3` | Nome usado nos exemplos do relatório para a interface monitorada |
| `/etc/suricata/rules/local.rules` | Arquivo das regras locais do experimento |
| `/var/log/suricata/fast.log` | Log textual acompanhado durante os testes |
| `/var/log/suricata/eve.json` | Log JSON usado para consulta alternativa dos alertas |

### 3) Pacotes usados no laboratório

* `dnsutils`, `net-tools`, `curl`, `wget`
* `suricata`, `tcpdump`, `jq`

---

## IV. Instalação e Preparação

> Se a interface indicada por `ip route get 1.1.1.1` não for `enp0s3`, substitua apenas esse nome nos comandos de inicialização e captura que usam a interface de rede.
> Mantenha essa interface anotada antes de seguir, pois ela será usada na inicialização do Suricata e nos comandos de verificação do laboratório.

### 1) Preparar o ambiente no VirtualBox

* **VM:** `user 1 - Debian`
* **Adapter 1:** **NAT** (DHCP do VirtualBox)

<img width="800" height="372" alt="image" src="https://github.com/user-attachments/assets/518f2ddb-4262-4f51-bb8d-7c9dd8cb2e6b" />

* **Recursos da VM:** **6 GB de RAM** e **3 núcleos de CPU**

<img width="462" height="126" alt="image" src="https://github.com/user-attachments/assets/11c305c2-950f-4493-996b-427af0095074" />


* **Iniciar a VM**

> **Ao final desta etapa:** a VM deve estar configurada em **NAT**, com os recursos previstos e pronta para receber endereçamento via DHCP.

### 2) Após iniciar a VM, conferir a rede e padronizar o DHCP

#### A) Padronizar a interface em DHCP

```bash
IFACE=$(ip route | awk '/default/ {print $5; exit}')
sudo dhclient -r "$IFACE" || true
sudo ip addr flush dev "$IFACE"
sudo dhclient "$IFACE"
ip -4 a show "$IFACE"
```

<img width="726" height="235" alt="image" src="https://github.com/user-attachments/assets/905455e8-4a02-4a6a-ab2e-5e7f0ebad5d7" />

#### B) Validar IP, saída para Internet e interface monitorada

```bash
ip a                    # deve obter IP 10.0.2.x (NAT do VBox)
ping -c2 1.1.1.1        # checar saída para internet
ip route get 1.1.1.1    # confirmar interface de saída (ex.: enp0s3)
```

<img width="1052" height="538" alt="image" src="https://github.com/user-attachments/assets/50ad173d-5d56-426f-bc52-58c3e6b848a3" />

> **Resultado esperado:** a VM deve apresentar um IP coerente com a rede NAT do VirtualBox, alcançar `1.1.1.1` e indicar a interface de saída usada pelo tráfego observado no laboratório.

> **Ao final desta etapa:** a conectividade externa e a interface de monitoramento devem estar confirmadas antes da instalação do Suricata.

### 3) Preparar o sistema antes da instalação

#### A) Prevenir lock do `apt`

```bash
sudo systemctl stop packagekit || true
sudo pkill -x packagekitd || true
sudo dpkg --configure -a
```

<img width="488" height="87" alt="image" src="https://github.com/user-attachments/assets/d30e0ae4-9ecf-491a-8501-b15edcc568c7" />

> **Ao final desta etapa:** o sistema deve estar liberado para instalar os pacotes do laboratório sem conflito de gerenciador de pacotes.

### 4) Instalar utilitários e Suricata

```bash
sudo apt update && sudo apt install -y dnsutils net-tools curl wget suricata tcpdump jq
```

<img width="913" height="425" alt="image" src="https://github.com/user-attachments/assets/4ea2ec37-be75-4134-965c-24403e454204" />

> **Ao final desta etapa:** todas as ferramentas necessárias para gerar tráfego, monitorar a rede e consultar alertas devem estar instaladas.

### 5) Criar e validar as regras locais

#### A) Entender o papel das regras

> **O que cada regra faz (antes do código):**
>
> * **SID 1002001 (URI):** alerta quando a **URI** da requisição HTTP contém `/SURICATA_BROWSER_URI_01`. Demonstra **inspeção de caminho** (HTTP em claro).
> * **SID 1002002 (BODY/POST):** alerta quando o **corpo** da requisição HTTP contém `SURICATA_BROWSER_BODY_02`. Demonstra **inspeção de payload** em **POST/PUT**.
> * **SID 1002003 (HEADER):** alerta quando um **cabeçalho HTTP** contém `X-Trigger-Lab: 1`. Demonstra **inspeção de cabeçalhos** (ex.: segurança, conformidade, políticas).
> * **SID 1002004 (DNS):** alerta quando a **consulta DNS** contém `suricata-trigger-lab.example`. Demonstra **visibilidade de DNS** mesmo que o domínio não exista.

> **Arquivo:** `/etc/suricata/rules/local.rules` (uma **linha por regra**)

#### B) Criar o arquivo `local.rules`

```bash
sudo tee /etc/suricata/rules/local.rules >/dev/null <<'RULES'
alert http any any -> any any (msg:"CUSTOM BROWSER - HTTP URI trigger"; flow:to_server; http.uri; content:"/SURICATA_BROWSER_URI_01"; nocase; sid:1002001; rev:4; classtype:web-application-activity; priority:2;)
alert http any any -> any any (msg:"CUSTOM BROWSER - HTTP client body trigger"; flow:to_server; http.request_body; content:"SURICATA_BROWSER_BODY_02"; nocase; sid:1002002; rev:4; classtype:web-application-attack; priority:2;)
alert http any any -> any any (msg:"CUSTOM BROWSER - HTTP header X-Trigger-Lab"; flow:to_server; content:"X-Trigger-Lab|3a| 1"; http_header; nocase; sid:1002003; rev:5; classtype:attempted-recon; priority:2;)
alert udp any any -> any 53 (msg:"CUSTOM BROWSER - DNS query trigger"; dns.query; content:"suricata-trigger-lab.example"; nocase; sid:1002004; rev:3; classtype:attempted-recon; priority:3;)
RULES
```

<img width="1106" height="233" alt="image" src="https://github.com/user-attachments/assets/5ab11d4f-11c8-4de4-ac55-a93533803b58" />

#### C) Validar a sintaxe das regras

```bash
sudo suricata -T -S /etc/suricata/rules/local.rules -v
# esperado: "4 rules successfully loaded, 0 failed"
```

<img width="1178" height="391" alt="image" src="https://github.com/user-attachments/assets/480cb59f-ded9-49f3-bfbf-3d3b8d5fdedb" />

> **Ao final desta etapa:** o arquivo de regras deve existir e o Suricata deve confirmar o carregamento correto das **4 regras locais**.

### 6) Iniciar o Suricata em modo IDS e verificar a operação

> Em Debian, usar `--set outputs.*` pode causar erro de “child node (null)”. Usaremos o YAML padrão.

#### A) Subir o Suricata manualmente

```bash
# parar instâncias anteriores e limpar pid/log
sudo systemctl stop suricata
sudo pkill -x suricata || true
sudo rm -f /var/run/suricata.pid /var/log/suricata/fast.log

# subir em daemon na interface correta (ex.: enp0s3)
# se sua interface tiver outro nome, descubra com: ip route get 1.1.1.1
sudo suricata -i enp0s3 -S /etc/suricata/rules/local.rules -l /var/log/suricata -D

# conferir que está ativo
ps aux | grep '[s]uricata'
sudo tail -n 15 /var/log/suricata/suricata.log
```

<img width="1176" height="677" alt="image" src="https://github.com/user-attachments/assets/bb721063-caf0-46e3-947c-1a2e5157cdea" />

#### B) Confirmar onde os alertas serão acompanhados

**Onde ver alertas:** `tail -f /var/log/suricata/fast.log`

**Alternativa JSON:** `jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | tail -n 5`

> **Ao final desta etapa:** o Suricata deve estar ativo em modo IDS, carregando `local.rules` e com os arquivos de log prontos para a observação dos testes.

---

## V. Procedimentos (Passo a Passo — **user 1 - Debian ↔ Internet**)

### Checklist antes dos testes

Antes de iniciar os cenários, confirme:

* as **4 regras locais** foram validadas com `suricata -T`;
* o processo do **Suricata** está em execução;
* o terminal de acompanhamento do `fast.log` está aberto;
* a interface monitorada foi identificada previamente (ex.: **`enp0s3`**);
* a VM possui conectividade para gerar o tráfego HTTP e DNS do experimento.

### Organização dos terminais

Abra dois terminais:

**Terminal A:** `tail -f /var/log/suricata/fast.log`

<img width="611" height="91" alt="image" src="https://github.com/user-attachments/assets/f7e2bad4-8a20-4919-979f-dd084d40962b" />

**Terminal B (caso optar por testar usando `curl` diretamente no terminal):** comandos de disparo (abaixo). Dica: force IPv4 com `-4`.

### Cenário 1 — **HTTP URI (SID 1002001)**

**O que este teste demonstra:** que o Suricata consegue **inspecionar a URI** (caminho) de uma requisição HTTP e gerar alerta quando encontra a **string-alvo**.

#### A) Executar o gatilho

```bash
curl -4 -s 'http://neverssl.com/SURICATA_BROWSER_URI_01' >/dev/null
# ou navegador: http://neverssl.com/SURICATA_BROWSER_URI_01
```

* Caso demore para executar ou alertar, aguarde. Este comportamento é esperado.

<img width="1785" height="207" alt="image" src="https://github.com/user-attachments/assets/75343aec-013b-4504-be75-92acb3f86fa6" />

#### B) Observar o alerta no log

**O que observar no log:** uma linha no `fast.log` com a mensagem
`CUSTOM BROWSER - HTTP URI trigger` (SID 1002001), indicando tráfego `{TCP} <IP_VM>:<porta> -> <IP_destino>:80`.

> **Ao final deste cenário:** deve existir evidência de que a regra de **URI** foi acionada pelo tráfego HTTP gerado.

---

### Cenário 2 — **HTTP BODY/POST (SID 1002002)**

**O que este teste demonstra:** que o Suricata consegue **inspecionar o corpo** (payload) de uma **requisição HTTP** (POST/PUT) e alertar quando a **string** estiver presente.

#### A) Executar o gatilho

```bash
curl -4 -s -X POST -d 'SURICATA_BROWSER_BODY_02' 'http://neverssl.com/' >/dev/null
# (opcional para ver o request) curl -4 -v -X POST -d 'SURICATA_BROWSER_BODY_02' 'http://neverssl.com/' >/dev/null
```

* Caso demore para executar ou alertar, aguarde. Este comportamento é esperado.

<img width="1785" height="218" alt="image" src="https://github.com/user-attachments/assets/24087409-8c8b-4a65-b4f8-8fe91cf8ccb7" />

#### B) Observar o alerta no log

**O que observar no log:** a mensagem
`CUSTOM BROWSER - HTTP client body trigger` (SID 1002002).
Se não disparar de primeira, rode com `-v` e valide que o **POST** saiu; rode novamente.

> **Ao final deste cenário:** deve existir evidência de que a regra de **corpo da requisição** foi acionada.

---

### Cenário 3 — **HTTP HEADER (SID 1002003)**

**O que este teste demonstra:** que o Suricata consegue **inspecionar cabeçalhos HTTP** e gerar alerta quando um **cabeçalho customizado** (`X-Trigger-Lab: 1`) está presente.

#### A) Executar o gatilho

```bash
curl -4 -s -H 'X-Trigger-Lab: 1' 'http://neverssl.com/' >/dev/null
# (opcional verbose) curl -4 -v -H 'X-Trigger-Lab: 1' 'http://neverssl.com/' >/dev/null
```

* Caso demore para executar ou alertar, aguarde. Este comportamento é esperado.

<img width="1782" height="256" alt="image" src="https://github.com/user-attachments/assets/6f87fb49-cc08-4880-9b18-6cc2c3657e72" />

#### B) Observar o alerta no log

**O que observar no log:** a mensagem
`CUSTOM BROWSER - HTTP header X-Trigger-Lab` (SID 1002003), com fluxo `{TCP} <IP_VM>:<porta> -> <IP_destino>:80`.

> **Ao final deste cenário:** deve existir evidência de que a regra de **cabeçalho HTTP** foi acionada.

---

### Cenário 4 — **DNS (SID 1002004)**

**O que este teste demonstra:** que o Suricata enxerga **consultas DNS** (nomes de domínio) e alerta quando a consulta contém o **domínio-alvo**.

#### A) Executar o gatilho

```bash
dig +short suricata-trigger-lab.example >/dev/null
# ou navegador: http://suricata-trigger-lab.example/
```

* Caso demore para executar ou alertar, aguarde. Este comportamento é esperado.

<img width="1777" height="287" alt="image" src="https://github.com/user-attachments/assets/5cb962e1-b239-4938-ac74-6255a2d782f4" />

#### B) Observar o alerta no log

**O que observar no log:** a mensagem
`CUSTOM BROWSER - DNS query trigger` (SID 1002004), com fluxo `{UDP} <IP_VM>:<porta> -> <DNS_resolvedor>:53`.

> **Ao final deste cenário:** deve existir evidência de que a regra de **consulta DNS** foi acionada.

---

## VI. Verificação e Resultados

### 1) Checklist de sucesso do experimento

* `suricata -T` retorna `4 rules successfully loaded, 0 rules failed`.
* O Suricata permanece em execução (`ps aux | grep '[s]uricata'`) e sem erro crítico no `suricata.log`.
* Cada um dos quatro cenários gera o alerta correspondente em `fast.log` ou `eve.json`.

### 2) Quadro comparativo (cenários)

| Cenário | Tráfego                      | Regra envolvida (msg)                        | SID     | Resultado esperado | Onde verificar     |
| :-----: | ---------------------------- | -------------------------------------------- | ------- | ------------------ | ------------------ |
|    1    | user 1 - Debian → Internet (HTTP/URI)    | `CUSTOM BROWSER - HTTP URI trigger`          | 1002001 | **Alertas**        | `fast.log` / `eve.json` |
|    2    | user 1 - Debian → Internet (HTTP/Body)   | `CUSTOM BROWSER - HTTP client body trigger`  | 1002002 | **Alertas**        | `fast.log` / `eve.json` |
|    3    | user 1 - Debian → Internet (HTTP/Header) | `CUSTOM BROWSER - HTTP header X-Trigger-Lab` | 1002003 | **Alertas**        | `fast.log` / `eve.json` |
|    4    | user 1 - Debian → Internet (DNS)         | `CUSTOM BROWSER - DNS query trigger`         | 1002004 | **Alertas**        | `fast.log` / `eve.json` |

### 3) Coleta rápida dos alertas

```bash
# Últimos alertas (formato fast)
tail -n 20 /var/log/suricata/fast.log

# Em JSON (EVE) com campos úteis, 1 por linha
jq -r 'select(.event_type=="alert") | "\(.timestamp) SID=\(.alert.signature_id) MSG=\(.alert.signature) \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"' \
  /var/log/suricata/eve.json | tail -n 10
```

> Use esta coleta rápida ao final dos cenários para consolidar a evidência dos alertas em formato textual ou JSON.


<img width="1900" height="338" alt="image" src="https://github.com/user-attachments/assets/8cbeaf01-02c1-49a8-9517-e756fd0f9a29" />

---

## VII. Conclusão

Com **Suricata na própria VM** e **regras locais** simples, comprovamos a detecção de **URI**, **cabeçalhos**, **corpo HTTP** e **consultas DNS** por meio de cenários objetivos e reproduzíveis. A configuração evita dependências externas e foca em **didática**, **auditoria** e **visibilidade** do tráfego **HTTP/DNS**.

---

## Apêndice — Troubleshooting rápido

* **Sem alertas no `fast.log`:**

  1. Confirme que o Suricata está **rodando**:
     `ps aux | grep '[s]uricata'`
  2. Veja o log de inicialização:
     `sudo tail -n 30 /var/log/suricata/suricata.log`
  3. Verifique **tráfego** efetivo na interface:
     `sudo tcpdump -ni enp0s3 'port 80 or port 53' -c 10`
     (se necessário, substitua `enp0s3` pela interface indicada por `ip route get 1.1.1.1`)

* **Erro “Failed to lookup configuration child node: (null)” ao iniciar:**
  Não use `--set outputs.*` no Debian. Inicie assim:
  `sudo suricata -i enp0s3 -S /etc/suricata/rules/local.rules -l /var/log/suricata -D`
  (se a interface não for `enp0s3`, ajuste o nome da interface)

* **`pidfile` “stale” / conflito de instância:**

  ```bash
  sudo systemctl stop suricata
  sudo pkill -x suricata || true
  sudo rm -f /var/run/suricata.pid
  ```

* **Regras não carregam / erros de sintaxe:**
  Cada regra deve estar **em uma única linha** (Snort-syntax). Valide com `-T`.

* **HTTP não dispara (HSTS/HTTPS forçado):**
  Use **`http://neverssl.com`** e force IPv4 com `curl -4`.

* **Confirmar que os triggers realmente estão saindo:**
  Para POST/HEADER, rode em paralelo:
  `sudo tcpdump -A -ni enp0s3 'port 80' -c 10`
  e verifique o **`POST`**, o **corpo** e o cabeçalho **`X-Trigger-Lab`** em texto.

* **Classificação diferente no log:**
  Dependendo do mapeamento interno de classificação, `classtype:attempted-recon` pode aparecer como **Attempted Information Leak** no `fast.log`.
