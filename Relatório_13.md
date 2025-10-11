# T02 – Redes de Dados I

# Relatório 13: TLS em HTTP e MQTT com Wireshark (VMs no VirtualBox)

Este relatório tem como objetivo **montar um laboratório em **NAT Network** (rede NAT do VirtualBox)** para demonstrar o uso de **TLS** nos protocolos **HTTP** e **MQTT**, comparar o tráfego em texto claro (HTTP/MQTT sem TLS) e criptografado (HTTPS/MQTT com TLS) e **analisar as diferenças no Wireshark**.

---

## I. Introdução

Nesta atividade, você configurará duas VMs (Servidor e Cliente) em uma **NAT Network** do VirtualBox para observar, via Wireshark no Cliente (VM2), como o TLS protege o conteúdo das mensagens em HTTP e MQTT. Em texto claro, o payload é legível; com TLS, apenas metadados e o **handshake** ficam visíveis.

**Pilares abordados:** foco em **Confidencialidade** (com menção a Autenticidade/Integridade via certificados e MAC do TLS).

---

## II. Conceitos e Fundamentos

* **HTTP x HTTPS:** HTTPS = HTTP sobre TLS (camada de segurança entre transporte e aplicação).
* **MQTT:** protocolo publish/subscribe leve (IoT). Portas padrão: **1883 (sem TLS)** e **8883 (com TLS)**.
* **TLS (Handshake):** ClientHello → ServerHello (+ certificado) → *key exchange* → chaves de sessão → comunicação criptografada.
* **Certificados:** neste lab usaremos **autoassinado** (Apache) e **CA local + cert. servidor** (Mosquitto) para possibilitar a validação do lado do cliente.
* **Wireshark:** filtros úteis `http`, `mqtt`, `tcp.port == 1883 || tcp.port == 8883`, `tls`, `tls.handshake`.

---

## III. Ambiente e Topologia

**VirtualBox — NAT Network:** `NatNetwork`

* **VM1 – Servidor (Debian Desktop)**: Apache (80/443), Mosquitto Broker (1883/8883)
* **VM2 – Cliente (Debian Desktop)**: `curl` (HTTP), `mosquitto-clients` (MQTT) e **Wireshark** (captura local)

> **Configuração de Adaptadores (todas as VMs)**
> **Adapter único:** **Attached to:** *NAT Network*
> **Name:** `NatNetwork` (**DHCP: On**)
> (uma única placa por VM; Internet + comunicação entre VMs; sem endereçamento manual)

### 1) IPs via DHCP (sem endereçamento manual)

Com **NAT Network (NatNetwork)**, os IPs são atribuídos automaticamente por **DHCP**. Use o **`ip a`** para identificar o IP atual do **Servidor (VM1)** e do **Cliente (VM2)**. Anote o IP do servidor como **<IP_SERVIDOR>** e utilize-o em todos os testes.

### 2) No Cliente (VM2) — captura (Wireshark)

Abra o Wireshark com ```sudo wireshark``` e selecione a **interface da NAT Network** (a que mostra o IP do Cliente).
**Filtro geral:** `ip.addr == <IP_SERVIDOR>`

### 3) Pacotes necessários (resumo)

* **Servidor:** `apache2`, `openssl`, `mosquitto`, `mosquitto-clients`
* **Cliente:** `curl`, `mosquitto-clients`, `wireshark`

---

## IV. Instalação e Preparação

> **Pacotes por VM (Debian Desktop, NAT Network `NatNetwork`)**
>
> * **VM1 – Servidor:** `sudo apt update && sudo apt install -y apache2 openssl mosquitto mosquitto-clients`
> * **VM2 – Cliente:** `sudo apt update && sudo apt install -y curl mosquitto-clients wireshark`

### 0) **Preparar a rede (VirtualBox → Ferramentas → Redes NAT)**

1. **Abrir o gerenciador de redes NAT:**

   * No VirtualBox, clique em **“Ferramentas”** (ou *Tools*).
   * Clique em **“Redes NAT”** (ou *Network Manager* → **NAT Networks**).

2. **Se já existir `NatNetwork`, apenas confira se está configurada:**

   * **Name:** `NatNetwork`
   * **IPv4 Prefix:** verifique o prefixo (ex.: `10.0.2.0/24`).
   * **Habilitar DHCP**: Marcado.

3. **Se NÃO existir `NatNetwork`: criar uma:**

   * Clique em **“Criar”** (*Create*).
   * **Name:** `NatNetwork`
   * **IPv4 Prefix:** ex.: `10.0.2.0/24` (padrão)
   * Marque **Habilitar DHCP**.
   * Confirme com **Aplicar**.
   
   [![image.png](https://i.postimg.cc/dVtK6mCB/image.png)](https://postimg.cc/N5VVfXp9)

4. **Vincular cada VM à `NatNetwork`:**

   * Para **VM1** e **VM2** → **Configurações** (*Settings*) → **Rede** (*Network*).
   * **Adaptador 1** (*Adapter 1*) → **Conectado a:** *NAT Network* → **Nome:** `NatNetwork`.
   * OK e **iniciar** as VMs.
  
   [![image.png](https://i.postimg.cc/c4t3HwCP/image.png)](https://postimg.cc/mtRkpcQS)

5. **Verificação rápida dentro das VMs:**

   ```bash
   ip a                          # verificar IPs (devem estar no mesmo prefixo, ex.: 10.0.2.x)
   ping -c2 <IP_SERVIDOR>        # da VM2 para a VM1
   ```

   > Se o ping falhar, confira se **ambas** estão realmente em **NAT Network (NatNetwork)** (e não em “NAT” simples).
   
   [![image.png](https://i.postimg.cc/tgsNHTwm/image.png)](https://postimg.cc/FfQLy99j)

### A) Servidor (VM1)

**Atualizar e instalar:**
**comando:**

```bash
sudo apt update && sudo apt install -y apache2 openssl mosquitto mosquitto-clients
```

**Criar página de teste (conteúdo identificável):**
**comando:**

```bash
echo "<h1>HELLO_TLS_HTTP</h1>" | sudo tee /var/www/html/index.html
```

**Verificar serviços e portas:**
**comando:**

```bash
sudo systemctl enable --now apache2 mosquitto
ss -tulpn | egrep "(80|1883)"
```

**Mosquitto — preparar listener 1883 em rede (pré-cenários):**
**comando:**
```bash
sudo systemctl stop mosquitto
sudo rm -f /etc/mosquitto/conf.d/00-disable-default.conf  # NÃO use 'port 0' no Mosquitto 2.x
sudo tee /etc/mosquitto/conf.d/plain.conf >/dev/null <<'EOF'
listener 1883 0.0.0.0
allow_anonymous true
EOF
sudo systemctl restart mosquitto
sudo ss -lntp | grep :1883   # esperado: 0.0.0.0:1883
```

### B) Cliente (VM2)

**Instalar clientes HTTP/MQTT e Wireshark:**
**comando:**

```bash
sudo apt update && sudo apt install -y curl mosquitto-clients wireshark
sudo dpkg-reconfigure wireshark-common   # escolha "Yes"
sudo usermod -aG wireshark $USER
newgrp wireshark
```

**No Cliente (VM2) — captura (Wireshark):** Abrir o Wireshark com o comando ```sudo wireshark``` e selecionar a interface da NAT Network (a que mostra o IP do Cliente).**
**Filtro geral:** `ip.addr == <IP_SERVIDOR>`

```bash
sudo wireshark
```
[![image.png](https://i.postimg.cc/8krw9grB/image.png)](https://postimg.cc/c60Qtjhr)
---

## V. Procedimentos (Passo a Passo)

### Cenário 1 — HTTP **sem TLS** (porta 80)

1. **No Cliente (VM2) — teste HTTP:**
   **comando:**

   ```bash
   curl -v http://<IP_SERVIDOR>
   ```
2. **No Cliente (VM2) — captura (Wireshark):** usar filtro `http`.
   **O que observar:** requisição `GET / HTTP/1.1` e resposta `200 OK` com **payload legível** (HTML contendo `HELLO_TLS_HTTP`).

[![image.png](https://i.postimg.cc/J407MKMB/image.png)](https://postimg.cc/JGwCQNy1)

### Cenário 2 — HTTP **com TLS** (HTTPS na porta 443)

**No Servidor (VM1):**

1. **Ativar SSL no Apache:**
   **comando:**

   ```bash
   sudo a2enmod ssl
   sudo a2ensite default-ssl
   sudo systemctl reload apache2
   ```
2. **Gerar certificado autoassinado (1 ano):**
   **comando:**

   ```bash
   sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout /etc/ssl/private/apache.key \
     -out /etc/ssl/certs/apache.crt \
     -subj "/C=BR/ST=MG/L=Inatel/O=Lab/OU=NetSec/CN=<IP_SERVIDOR>"
   ```
3. **Apontar o vhost SSL para o certificado/ chave** (verifique os caminhos em `/etc/apache2/sites-available/default-ssl.conf`):
   **comando:**

   ```bash
   sudo sed -i 's#SSLCertificateFile .*#SSLCertificateFile /etc/ssl/certs/apache.crt#' /etc/apache2/sites-available/default-ssl.conf
   sudo sed -i 's#SSLCertificateKeyFile .*#SSLCertificateKeyFile /etc/ssl/private/apache.key#' /etc/apache2/sites-available/default-ssl.conf
   sudo systemctl restart apache2
   ss -tulpn | grep :443
   ```
4. **No Cliente (VM2) — teste HTTPS:** (ignorar verificação CA com `-k`):
   **comando:**

   ```bash
   curl -vk https://<IP_SERVIDOR>
   ```
5. **No Cliente (VM2) — captura (Wireshark):** filtro `tls` ou `tcp.port == 443`.
   **O que observar:** pacotes de **handshake TLS** (ClientHello/ServerHello, Certificado) e **payload cifrado**.
[![image.png](https://i.postimg.cc/gcq4mqNz/image.png)](https://postimg.cc/Lh5jVPcw)
---

### Cenário 3 — MQTT **sem TLS** (porta 1883)

1. **No Servidor (VM1) — habilitar listener 1883 acessível na rede:**
   **comando:**

   ```bash
   sudo tee /etc/mosquitto/conf.d/plain.conf >/dev/null <<'EOF'
   listener 1883 0.0.0.0
   allow_anonymous true
   EOF
   sudo systemctl restart mosquitto
   ss -lntp | grep :1883 # esperado: 0.0.0.0:1883
   ```
2. **No Cliente (VM2), abrir dois terminais:**
   **Terminal A — subscribe:**
   **comando:**

   ```bash
   mosquitto_sub -h <IP_SERVIDOR> -t "teste"
   ```

   **Terminal B — publish:**
   **comando:**

   ```bash
   mosquitto_pub -h <IP_SERVIDOR> -t "teste" -m "Mensagem sem TLS"
   ```
3. **No Cliente (VM2) — captura (Wireshark):** filtro `mqtt` ou `tcp.port == 1883`.
   **O que observar:** pacotes `CONNECT`, `CONNACK`, `PUBLISH` e **payload legível** (string `Mensagem sem TLS`).

    *(Mensagens aparecerão no Terminal A do `mosquitto_sub`)*
    
[![image.png](https://i.postimg.cc/7bvy3FQM/image.png)](https://postimg.cc/y3T5BbKk)

---

### Cenário 4 — MQTT **com TLS** (porta 8883)

> Aqui faremos **CA local** e um **certificado de servidor** para o Mosquitto. O cliente usará a `ca.crt` para validar o broker.

**No Servidor (VM1):**

1. **Gerar CA local (VM1):**
   **comando:**

   ```bash
   sudo install -d -m 755 /etc/mosquitto/certs
   cd /etc/mosquitto/certs
   sudo openssl genrsa -out ca.key 2048
   sudo openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
     -subj "/C=BR/ST=MG/L=Inatel/O=Lab/OU=MQTT-CA/CN=lab-mosquitto-ca"
   ```

2. **Gerar chave/CSR do servidor e assinar com a CA (VM1):**
   **comando:**

   ```bash
   cd /etc/mosquitto/certs
   sudo openssl genrsa -out server.key 2048
   sudo openssl req -new -key server.key -out server.csr \
     -subj "/C=BR/ST=MG/L=Inatel/O=Lab/OU=MQTT/CN=<IP_SERVIDOR>"
   sudo openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
     -out server.crt -days 365 -sha256
   ls -l /etc/mosquitto/certs
   ```

3. **Configurar listener TLS do Mosquitto (VM1):**
   **comando:**

   ```bash
   echo "listener 8883 0.0.0.0
   allow_anonymous true
   cafile /etc/mosquitto/certs/ca.crt
   certfile /etc/mosquitto/certs/server.crt
   keyfile /etc/mosquitto/certs/server.key" | \
   sudo tee /etc/mosquitto/conf.d/tls.conf

   # IMPORTANTE: permitir que o serviço 'mosquitto' leia os arquivos
   sudo chown mosquitto:mosquitto /etc/mosquitto/certs/{ca.crt,server.crt,server.key}
   sudo chmod 640 /etc/mosquitto/certs/server.key
   sudo chmod 644 /etc/mosquitto/certs/{server.crt,ca.crt}

   sudo systemctl restart mosquitto
   ss -tulpn | egrep "(1883|8883)"   # esperado: 0.0.0.0:8883
   ```

4. **Transferir a `ca.crt` para o Cliente (VM2) — via HTTP pelo Apache (método padrão):**
   No Servidor (VM1): copiar a CA para a raiz pública do Apache:
   **comando:**

   ```bash
   sudo cp /etc/mosquitto/certs/ca.crt /var/www/html/ca.crt
   sudo chmod 644 /var/www/html/ca.crt
   ls -l /var/www/html/ca.crt
   ```
   No Cliente (VM2) baixar a CA via `curl`:
   **comando:**
   
   ```bash
   curl -f http://<IP_SERVIDOR>/ca.crt -o ~/ca.crt
   ```

5. **No Cliente (VM2) — teste TLS (porta 8883):**
   **Terminal A — subscribe:**
   **comando:**

   ```bash
   mosquitto_sub --cafile ~/ca.crt -h <IP_SERVIDOR> -p 8883 -t "teste"
   ```

   **Terminal B — publish:**
   **comando:**

   ```bash
   mosquitto_pub --cafile ~/ca.crt -h <IP_SERVIDOR> -p 8883 -t "teste" -m "Mensagem com TLS"
   ```

6. **No Cliente (VM2) — captura (Wireshark):** filtro `tcp.port == 8883` ou `tls`.
   **O que observar:** handshake TLS e **payload cifrado** (não deve aparecer a string `Mensagem com TLS`).

[![image.png](https://i.postimg.cc/28z5KvH6/image.png)](https://postimg.cc/mh5RccWf)

---

## VI. Verificação e Resultados

### 1) Quadro comparativo

| Protocolo | Porta | TLS | Visível no Wireshark                                                 | Payload                               |
| --------- | ----: | :-: | -------------------------------------------------------------------- | ------------------------------------- |
| HTTP      |    80 | Não | Métodos/URLs, cabeçalhos, corpo                                      | **Legível** (ex.: `HELLO_TLS_HTTP`)   |
| HTTPS     |   443 | Sim | Handshake (ClientHello/ServerHello/Cert), chaves, *Application Data* | **Ilegível**                          |
| MQTT      |  1883 | Não | CONNECT/CONNACK/SUBSCRIBE/PUBLISH (tópico, flags)                    | **Legível** (ex.: `Mensagem sem TLS`) |
| MQTT      |  8883 | Sim | Handshake TLS, *Application Data*                                    | **Ilegível**                          |

### 2) Filtros práticos (copiar/colar)

* HTTP claro: `http`
* HTTPS: `tls`  *(ou `tcp.port == 443`)*
* MQTT claro: `mqtt`  *(ou `tcp.port == 1883`)*
* MQTT/TLS: `tcp.port == 8883`
* Handshake específico: `tls.handshake`
* Verificar presença de string (apenas no claro): `frame contains "HELLO_TLS_HTTP"` ou `frame contains "Mensagem sem TLS"`

---

## VII. Conclusão

Foi demonstrado, de forma prática, que a adoção de **TLS** em HTTP e MQTT protege a **confidencialidade** das mensagens. Enquanto no tráfego sem TLS é possível ler o **payload** em claro (HTML e mensagens MQTT), no tráfego com TLS o Wireshark exibe apenas metadados do **handshake** e pacotes **cifrados**, inviabilizando a leitura do conteúdo sem as chaves de sessão.

---

## Anexos (inserir prints)

* **Figura 1 —** HTTP sem TLS: `GET /` e `200 OK` com corpo legível.
* **Figura 2 —** Handshake TLS no HTTPS (ClientHello/ServerHello/Certificate).
* **Figura 3 —** MQTT sem TLS: `PUBLISH` com payload `Mensagem sem TLS`.
* **Figura 4 —** MQTT com TLS: `Application Data` cifrado (porta 8883).

---

## Apêndice — Troubleshooting rápido

* **Não vejo o tráfego no Wireshark (VM2):** confirme que está capturando na interface da NAT Network (verifique com `ip -br a`) e que há tráfego sendo gerado (execute `curl`/`mosquitto_*` no VM2).
* **Interface diferente de `enp0s3`:** ajuste o nome no netplan.
* **HTTPS não sobe:** verifique caminhos do `SSLCertificateFile` e `SSLCertificateKeyFile` no `default-ssl.conf`.
* **Mosquitto 8883 não abre:** cheque `/etc/mosquitto/conf.d/tls.conf` e permissões de arquivos em `/etc/mosquitto/certs`.
* **Cliente MQTT não valida o broker:** garanta que usa `--cafile ~/ca.crt` que corresponde à CA que assinou `server.crt`.
* **Sem captura no Wireshark:** adicione o usuário ao grupo `wireshark` e reabra a sessão (`newgrp wireshark`).
