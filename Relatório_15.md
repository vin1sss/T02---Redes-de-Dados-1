# T02 – Redes de Dados I

# Relatório 15: Configuração de **IDS** de Rede usando **Suricata no Debian (1 VM)**

Este relatório descreve a configuração de um **IDS** com **Suricata** **diretamente no Debian (uma única VM)**, monitorando o tráfego da própria VM para a **Internet**. Usaremos **apenas regras locais (Custom Rules)**, sem baixar rulesets externos. O objetivo é **instalar**, **iniciar** o Suricata em **modo IDS**, **gerar tráfego didático** (via navegador/`curl`) e **analisar os alertas** no `fast.log`/`eve.json`.

> **Importante:** Todos os cenários são **seguros e reprodutíveis** no laboratório.

---

## I. Introdução

A única VM (Debian Desktop) atuará como **sensor IDS** (Suricata) e como **cliente** que gera tráfego. As regras locais foram desenhadas para disparar alertas de forma controlada e didática (URI, BODY/POST, HEADER e DNS).

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

**VirtualBox (1 VM):**

* **VM1 (Debian Desktop, com Suricata)**

  * **Adapter 1:** **NAT** (DHCP do VirtualBox)

> **Topologia:** **VM1 ↔ NAT (VBox) ↔ Internet**. O Suricata escuta a **interface de saída** (tipicamente `enp0s3`).

[![image.png](https://i.postimg.cc/kgVZ7c1P/image.png)](https://postimg.cc/dhYnB8c5)

---

## IV. Instalação e Preparação

### 0) Verificações iniciais

```bash
ip a                    # deve obter IP 10.0.2.x (NAT do VBox)
ping -c2 1.1.1.1        # checar saída para internet
ip route get 1.1.1.1    # confirmar interface de saída (ex.: enp0s3)
```

[![image.png](https://i.postimg.cc/cHZdzHR5/image.png)](https://postimg.cc/NyJh9QP1)

### A) Instalar utilitários e Suricata

```bash
sudo apt update && sudo apt install -y dnsutils net-tools curl wget suricata tcpdump jq
```

### B) Regras locais (Suricata 7 — sticky buffers + classtype)

> **O que cada regra faz (antes do código):**
>
> * **SID 1002001 (URI):** alerta quando a **URI** da requisição HTTP contém `/**SURICATA_BROWSER_URI_01**`. Demonstra **inspeção de caminho** (HTTP em claro).
> * **SID 1002002 (BODY/POST):** alerta quando o **corpo** da requisição HTTP contém `**SURICATA_BROWSER_BODY_02**`. Demonstra **inspeção de payload** em **POST/PUT**.
> * **SID 1002003 (HEADER):** alerta quando um **cabeçalho HTTP** contém `**X-Trigger-Lab: 1**`. Demonstra **inspeção de cabeçalhos** (ex.: segurança, conformidade, políticas).
> * **SID 1002004 (DNS):** alerta quando a **consulta DNS** contém `**suricata-trigger-lab.example**`. Demonstra **visibilidade de DNS** mesmo que o domínio não exista.

> **Arquivo:** `/etc/suricata/rules/local.rules` (uma **linha por regra**)

```bash
sudo tee /etc/suricata/rules/local.rules >/dev/null <<'RULES'
alert http any any -> any any (msg:"CUSTOM BROWSER - HTTP URI trigger"; flow:to_server; http.uri; content:"/SURICATA_BROWSER_URI_01"; nocase; sid:1002001; rev:4; classtype:web-application-activity; priority:2;)
alert http any any -> any any (msg:"CUSTOM BROWSER - HTTP client body trigger"; flow:to_server; http.request_body; content:"SURICATA_BROWSER_BODY_02"; nocase; sid:1002002; rev:4; classtype:web-application-attack; priority:2;)
alert http any any -> any any (msg:"CUSTOM BROWSER - HTTP header X-Trigger-Lab"; flow:to_server; content:"X-Trigger-Lab|3a| 1"; http_header; nocase; sid:1002003; rev:5; classtype:attempted-recon; priority:2;)
alert udp any any -> any 53 (msg:"CUSTOM BROWSER - DNS query trigger"; dns.query; content:"suricata-trigger-lab.example"; nocase; sid:1002004; rev:3; classtype:attempted-recon; priority:3;)
RULES
```

[![image.png](https://i.postimg.cc/c41BSB1d/image.png)](https://postimg.cc/kDZbN8tH)

**Validar sintaxe**:

```bash
sudo suricata -T -S /etc/suricata/rules/local.rules -v
# esperado: "4 rules successfully loaded, 0 failed"
```

[![image.png](https://i.postimg.cc/pdP2GrYZ/image.png)](https://postimg.cc/zyPZ3JQb)

### C) Iniciar o Suricata (modo IDS) — **manual, sem `--set`**

> Em Debian, usar `--set outputs.*` pode causar erro de “child node (null)”. Usaremos o YAML padrão.

```bash
# parar instâncias anteriores e limpar pid/log
sudo systemctl stop suricata
sudo pkill -x suricata || true
sudo rm -f /var/run/suricata.pid /var/log/suricata/fast.log

# subir em daemon na interface correta (ex.: enp0s3)
sudo suricata -i enp0s3 -S /etc/suricata/rules/local.rules -l /var/log/suricata -D

# conferir que está ativo
ps aux | grep '[s]uricata'
sudo tail -n 15 /var/log/suricata/suricata.log
```

[![image.png](https://i.postimg.cc/cJjdshGP/image.png)](https://postimg.cc/QBp2mptq)

**Onde ver alertas:** `tail -f /var/log/suricata/fast.log`

**Alternativa JSON:** `jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | tail -n 5`

---

## V. Procedimentos (Passo a Passo — **VM1 ↔ Internet**)

Abra dois terminais:

**Terminal A:** `tail -f /var/log/suricata/fast.log`

[![image.png](https://i.postimg.cc/SsvYbCgW/image.png)](https://postimg.cc/YGQC1GK9)

**Terminal B (caso optar por testar usando `curl` diretamente no terminal):** comandos de disparo (abaixo). Dica: force IPv4 com `-4`.

### Cenário 1 — **HTTP URI (SID 1002001)**

**O que este teste demonstra:** que o Suricata consegue **inspecionar a URI** (caminho) de uma requisição HTTP e gerar alerta quando encontra a **string-alvo**.

**Como executar:**

```bash
curl -4 -s 'http://neverssl.com/SURICATA_BROWSER_URI_01' >/dev/null
# ou navegador: http://neverssl.com/SURICATA_BROWSER_URI_01
```

[![image.png](https://i.postimg.cc/6qKrmdq8/image.png)](https://postimg.cc/njd9s9vx)

* Caso demorar para executar ou alertar, aguarde, este comportamento é esperado.

**O que observar no log:** uma linha no `fast.log` com a mensagem
`CUSTOM BROWSER - HTTP URI trigger` (SID **1002001**), indicando tráfego `{TCP} <IP_VM>:<porta> -> <IP_destino>:80`.

[![image.png](https://i.postimg.cc/7Z52XB9F/image.png)](https://postimg.cc/0zqjy0Ln)

---

### Cenário 2 — **HTTP BODY/POST (SID 1002002)**

**O que este teste demonstra:** que o Suricata consegue **inspecionar o corpo** (payload) de uma **requisição HTTP** (POST/PUT) e alertar quando a **string** estiver presente.

**Como executar:**

```bash
curl -4 -s -X POST -d 'SURICATA_BROWSER_BODY_02' 'http://neverssl.com/' >/dev/null
# (opcional para ver o request) curl -4 -v -X POST -d 'SURICATA_BROWSER_BODY_02' 'http://neverssl.com/' >/dev/null
```

[![image.png](https://i.postimg.cc/GmPC0RXQ/image.png)](https://postimg.cc/DSzDs9kJ)

**O que observar no log:** a mensagem
`CUSTOM BROWSER - HTTP client body trigger` (SID **1002002**).
Se não disparar de primeira, rode com `-v` e valide que o **POST** saiu; rode novamente.

[![image.png](https://i.postimg.cc/tCQq8B98/image.png)](https://postimg.cc/23GNZFbx)

---

### Cenário 3 — **HTTP HEADER (SID 1002003)**

**O que este teste demonstra:** que o Suricata consegue **inspecionar cabeçalhos HTTP** e gerar alerta quando um **cabeçalho customizado** (`X-Trigger-Lab: 1`) está presente.

**Como executar:**

```bash
curl -4 -s -H 'X-Trigger-Lab: 1' 'http://neverssl.com/' >/dev/null
# (opcional verbose) curl -4 -v -H 'X-Trigger-Lab: 1' 'http://neverssl.com/' >/dev/null
```

[![image.png](https://i.postimg.cc/vHtskMqz/image.png)](https://postimg.cc/Ln5wZdMY)

**O que observar no log:** a mensagem
`CUSTOM BROWSER - HTTP header X-Trigger-Lab` (SID **1002003**), com fluxo `{TCP} <IP_VM>:<porta> -> <IP_destino>:80`.

[![image.png](https://i.postimg.cc/ZnmQxvhc/image.png)](https://postimg.cc/FdPG9Rzd)

---

### Cenário 4 — **DNS (SID 1002004)**

**O que este teste demonstra:** que o Suricata enxerga **consultas DNS** (nomes de domínio) e alerta quando a consulta contém o **domínio-alvo**.

**Como executar:**

```bash
dig +short suricata-trigger-lab.example >/dev/null
# ou navegador: http://suricata-trigger-lab.example/
```

[![image.png](https://i.postimg.cc/FRyWzFJR/image.png)](https://postimg.cc/BLvcw0p9)

**O que observar no log:** a mensagem
`CUSTOM BROWSER - DNS query trigger` (SID **1002004**), com fluxo `{UDP} <IP_VM>:<porta> -> <DNS_resolvedor>:53`.

[![image.png](https://i.postimg.cc/65jHymyX/image.png)](https://postimg.cc/TpbjsQV7)

---

## VI. Verificação e Resultados

### 1) Quadro comparativo (cenários)

| Cenário | Tráfego                      | Regra envolvida (msg)                        | SID     | Resultado esperado | Onde verificar     |
| :-----: | ---------------------------- | -------------------------------------------- | ------- | ------------------ | ------------------ |
|    1    | VM1 → Internet (HTTP/URI)    | `CUSTOM BROWSER - HTTP URI trigger`          | 1002001 | **Alertas**        | `fast.log` / `eve` |
|    2    | VM1 → Internet (HTTP/Body)   | `CUSTOM BROWSER - HTTP client body trigger`  | 1002002 | **Alertas**        | `fast.log` / `eve` |
|    3    | VM1 → Internet (HTTP/Header) | `CUSTOM BROWSER - HTTP header X-Trigger-Lab` | 1002003 | **Alertas**        | `fast.log` / `eve` |
|    4    | VM1 → Internet (DNS)         | `CUSTOM BROWSER - DNS query trigger`         | 1002004 | **Alertas**        | `fast.log` / `eve` |

### 2) Coleta rápida de evidências (para anexar ao relatório)

```bash
# Últimos alertas (formato fast)
tail -n 20 /var/log/suricata/fast.log

# Em JSON (EVE) com campos úteis, 1 por linha
jq -r 'select(.event_type=="alert") | "\(.timestamp) SID=\(.alert.signature_id) MSG=\(.alert.signature) \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"' \
  /var/log/suricata/eve.json | tail -n 10
```

[![image.png](https://i.postimg.cc/tgHFT3tX/image.png)](https://postimg.cc/G4q4gs5N)

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

* **Erro “Failed to lookup configuration child node: (null)” ao iniciar:**
  Não use `--set outputs.*` no Debian. Inicie assim:
  `sudo suricata -i enp0s3 -S /etc/suricata/rules/local.rules -l /var/log/suricata -D`

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

---

## (Opcional) Executar como **serviço** permanente (PCAP em `enp0s3`)

```bash
sudo tee /etc/default/suricata >/dev/null <<'EOF'
RUN=yes
LISTENMODE=pcap
IFACE=enp0s3
SURICATA_OPTIONS="-S /etc/suricata/rules/local.rules"
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now suricata
systemctl status suricata --no-pager -n 10
```

> Se a interface mudar (ex.: `enp0s8`), atualize `IFACE=` e reinicie o serviço.
