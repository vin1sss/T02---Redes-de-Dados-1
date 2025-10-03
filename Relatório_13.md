# Relatório 13

**Cenário: TLS em HTTP e MQTT com Wireshark (VMs no VirtualBox)**

---

## Objetivo

* Montar um laboratório em **rede interna no VirtualBox** para demonstrar TLS nos protocolos HTTP e MQTT.
* Comparar tráfego em texto claro (HTTP/MQTT sem TLS) e criptografado (HTTPS/MQTT com TLS).
* Analisar as diferenças via **Wireshark**.

---

## Ambiente Proposto

* **VM1 – Servidor (Ubuntu Server)**

  * Apache HTTP (80/443)
  * Mosquitto MQTT Broker (1883/8883)

* **VM2 – Cliente (Ubuntu Desktop/Server)**

  * curl (HTTP)
  * mosquitto-clients (MQTT)

* **VM3 – Observador (Ubuntu/Kali)**

  * Wireshark

**Rede VirtualBox:** Internal Network `interna_lab`

* Servidor: `192.168.56.101`
* Cliente: `192.168.56.102`
* Observador: `192.168.56.103`

---

## Execução Planejada

### 1. HTTP sem TLS

* Instalar Apache no servidor:

  ```bash
  sudo apt update && sudo apt install apache2 -y
  ```
* Testar no cliente:

  ```bash
  curl http://192.168.56.101
  ```
* Esperado no Wireshark: conteúdo em texto claro.

---

### 2. HTTP com TLS

* Ativar SSL no Apache:

  ```bash
  sudo a2enmod ssl && sudo systemctl restart apache2
  ```
* Gerar certificado autoassinado:

  ```bash
  sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/apache.key \
  -out /etc/ssl/certs/apache.crt
  ```
* Testar no cliente:

  ```bash
  curl -k https://192.168.56.101
  ```
* Esperado: tráfego criptografado, apenas handshake visível.

---

### 3. MQTT sem TLS

* Instalar Mosquitto:

  ```bash
  sudo apt install mosquitto mosquitto-clients -y
  ```
* Publicar/assinar do cliente:

  ```bash
  mosquitto_sub -h 192.168.56.101 -t "teste"
  mosquitto_pub -h 192.168.56.101 -t "teste" -m "Mensagem sem TLS"
  ```
* Esperado no Wireshark: mensagens em texto claro.

---

### 4. MQTT com TLS

* Gerar certificado para Mosquitto:

  ```bash
  sudo openssl req -new -x509 -days 365 -nodes \
  -out /etc/mosquitto/certs/ca.crt \
  -keyout /etc/mosquitto/certs/ca.key
  ```
* Configurar Mosquitto para usar TLS na porta 8883.
* Testar no cliente:

  ```bash
  mosquitto_sub --cafile ca.crt -h 192.168.56.101 -p 8883 -t "teste"
  mosquitto_pub --cafile ca.crt -h 192.168.56.101 -p 8883 -t "teste" -m "Mensagem com TLS"
  ```
* Esperado: pacotes criptografados, payload ilegível.

---

## Resultados Esperados

* Demonstrar no Wireshark a diferença entre tráfego em **texto claro** e **criptografado**.
* Destacar a visualização do **handshake TLS**.
* Relacionar os experimentos ao pilar de **confidencialidade** em segurança da informação.
