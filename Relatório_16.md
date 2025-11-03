# T02 – Redes de Dados I

# **Relatório 16: Saindo do VirtualBox — Criando e testando HTTP e MQTT na nuvem pública da Azure**

Este relatório **replica o Relatório 04** (HTTP + MQTT em duas VMs) **só que na Azure**, com interface atual do portal. Você vai:

1. criar **Grupo de Recursos** e **Rede Virtual**;
2. criar **duas VMs** na mesma VNet (vm1-servidor e vm2-cliente);
3. **instalar e testar** Apache (HTTP) e Mosquitto (MQTT);
4. **monitorar** o tráfego com **tshark** (CLI do Wireshark).
   Os passos e comandos abaixo são **suficientes e autodidatas** para um aluno executar do zero.

---

## I. Introdução

A topologia final fica **100% em nuvem**:

```
Internet
   │
   └─ Portal Azure
        └─ RG: rg-t02
            └─ VNet: vnet-t02 (10.0.0.0/16)
                └─ Subnet: default (10.0.0.0/24)
                    ├─ vm1-servidor (Ubuntu 24.04)  [Apache + Mosquitto + tshark]
                    └─ vm2-cliente (Ubuntu 24.04)   [curl + mosquitto-clients]
```

**Objetivo**: repetir os testes do Relatório 04 (HTTP e MQTT em duas VMs) e observar pacotes com **tshark**.  

---

## II. Conceitos/Fundamentos (resumo didático)

* **HTTP** (porta 80): modelo **requisição–resposta**; vamos usar **Apache** como servidor web. 
* **MQTT** (porta 1883): modelo **publish/subscribe** via **broker** (Mosquitto). Tópicos e QoS fazem o roteamento confiável de mensagens. 
* **tshark (Wireshark CLI)**: captura e mostra pacotes (filtros por porta). No 16, filtra **HTTP 80** e **MQTT 1883**. 

---

## III. Ambiente e Pré-requisitos

* **Assinatura Azure** ativa.
* **Portal**: [https://portal.azure.com](https://portal.azure.com) (UI em PT).
* **Região**: se **East US** acusar indisponibilidade de tamanho (erro *NotAvailableForSubscription*), use **West US 2** (funcionou nos testes).
* **Tamanhos sugeridos**:

  * Preferencial: **Standard_D2s_v3** (2 vCPU/8 GiB).
  * Alternativa econômica: **B1ms** (1 vCPU/2 GiB), suficiente para a prática.

> Dica de UI: em **“Selecionar um tamanho de VM”**, use **“Ver todos os tamanhos”** e pesquise por **“D2s”** ou **“B1ms”**. Se não houver na região, **troque a região** ou **peça/atualize cota**.

---

## IV. Implementação na Azure (passo a passo)

### A) **Grupo de Recursos**

1. No menu esquerdo, **Grupos de recursos** → **Criar**.

[![image.png](https://i.postimg.cc/8zfcYbKd/image.png)](https://postimg.cc/68wB2CNT)

[![image.png](https://i.postimg.cc/L6Ym48th/image.png)](https://postimg.cc/Tp6zCGHX)

2. **Nome**: `rg-t02`. **Região**: (ex.) `West US 2`.

[![image.png](https://i.postimg.cc/J7yh0xmj/image.png)](https://postimg.cc/5jVJkwXt)

3. **Rever + criar** → **Criar**.

[![image.png](https://i.postimg.cc/pL0NDNJH/image.png)](https://postimg.cc/87rnS0YK)

### B) **Rede Virtual (VNet)**

1. No menu esquerdo, **Redes virtuais** → **Criar**.

[![image.png](https://i.postimg.cc/Gh5JYqTf/image.png)](https://postimg.cc/PP1wnb4b)

[![image.png](https://i.postimg.cc/W46k9ntz/image.png)](https://postimg.cc/Lq555jtF)

2. **RG ou Grupo de Recursos**: `rg-t02`. **Nome**: `vnet-t02`. **Região**: a mesma das VMs.

[![image.png](https://i.postimg.cc/9XSrYS18/image.png)](https://postimg.cc/Lht9HxcL)

3. Aba **Endereços IP**:

   * Espaço: `10.0.0.0/16`
   * Sub-rede **default**: `10.0.0.0/24`

[![image.png](https://i.postimg.cc/9F5qjK96/image.png)](https://postimg.cc/yWjNmfvj)

4. **Rever + criar** → **Criar**.

[![image.png](https://i.postimg.cc/BbMWNdfv/image.png)](https://postimg.cc/p5h1LcTN)

### C) **VM 1 — `vm1-servidor` (Ubuntu 24.04 LTS, x64 Gen2)**

1. No menu esquerdo, **Máquinas virtuais** → **Criar** → **Máquina virtual**.

[![image.png](https://i.postimg.cc/gJbnP6XN/image.png)](https://postimg.cc/3y9KXNZv)

[![image.png](https://i.postimg.cc/hGTtMPyJ/image.png)](https://postimg.cc/HJWmkHCH)

2. **RG/Grupo de Recursos**: `rg-t02`. **Nome**: `vm1-servidor`.
3. **Região**: `West US 2` (ou outra com tamanho disponível).

[![image.png](https://i.postimg.cc/rpr7rDhZ/image.png)](https://postimg.cc/Z9Jfk5z6)

4. **Imagem**: *Ubuntu Server 24.04 LTS – x64 Gen2*.
5. **Tamanho**: `Standard_B1ms` (ou `D2s_v3` se preferir).

[![image.png](https://i.postimg.cc/y8SLfwFP/image.png)](https://postimg.cc/w1g5M44y)

6. **Autenticação**: chave SSH (recomendado) ou senha (apenas laboratório).

[![image.png](https://i.postimg.cc/1X2pw37C/image.png)](https://postimg.cc/hQ8zqcBT)

7. **Regras de porta de entrada**: escolha **“Permitir portas selecionadas”** e marque **SSH (22)** e **HTTP (80)**.

   * A porta **1883/TCP** (MQTT) adicionaremos no NSG na etapa “Rede” da VM após criada.

[![image.png](https://i.postimg.cc/XJDF6vW3/image.png)](https://postimg.cc/1nw4ps4Y)

8. Aba **Rede**: garanta **VNet `vnet-t02`** e sub-rede **default**.

[![image.png](https://i.postimg.cc/MpDDHVJb/image.png)](https://postimg.cc/MnnRrcTv)

9. **Rever + criar** → **Criar**.

10. **Transferir chave privada e criar recurso**.

[![image.png](https://i.postimg.cc/ryfM1YGn/image.png)](https://postimg.cc/mh1vRj5C)

11. **Aguardar a conclusão da implementação**

[![image.png](https://i.postimg.cc/3rczJMFp/image.png)](https://postimg.cc/4npWBSMN)

### D) **VM 2 — `vm2-cliente`**

Repita a criação com **mesmos RG/VNet/Sub-rede**. **Portas de entrada**: **apenas SSH (22)**.

[![image.png](https://i.postimg.cc/sXSKV8j3/image.png)](https://postimg.cc/N9sRDd2n)

[![image.png](https://i.postimg.cc/fWfjBYJS/image.png)](https://postimg.cc/PNNwqpbd)

[![image.png](https://i.postimg.cc/NM7TCwG4/image.png)](https://postimg.cc/MMHvXNQM)

[![image.png](https://i.postimg.cc/0N7JrqSk/image.png)](https://postimg.cc/8FPCn9w9)

[![image.png](https://i.postimg.cc/vBQDBxMv/image.png)](https://postimg.cc/HJhTvxrJ)

[![image.png](https://i.postimg.cc/MpFhHCSs/image.png)](https://postimg.cc/gx3MBBrR)

[![image.png](https://i.postimg.cc/BQDgHRHT/image.png)](https://postimg.cc/7fH0ysBh)

[![image.png](https://i.postimg.cc/gk5DZmx6/image.png)](https://postimg.cc/F7y3ttg9)

### E) **Abrir porta 1883/TCP (MQTT) para a vm1-servidor**

1. Entre na **vm1-servidor** → **Redes** → **Definições de rede** → **Criar regra de portas** → **Regra de porta de entrada**.
2. **Intervalos de portas de destino**: `1883`, **Protocolo**: `TCP`, **Ação**: **Permitir**, **Prioridade**: `1000–2000`, **Nome**: `allow-mqtt-1883`.
3. Adicionar.

[![image.png](https://i.postimg.cc/3JMqsXB7/image.png)](https://postimg.cc/0rfZmJFH)

---

## V. Configuração dentro das VMs

> Todos os comandos são em **Português** (prefixo **comando:**). Execute via SSH no **Ubuntu**.

### 1) **vm1-servidor** — instalar serviços e preparar MQTT

**Atualizar o sistema e instalar pacotes:**

```bash
# comando: atualizar o sistema
sudo apt update && sudo apt upgrade -y

# comando: instalar Apache (HTTP) e Mosquitto (broker MQTT) + clientes e tshark
sudo apt install -y apache2 mosquitto mosquitto-clients tshark curl
```

(Instalação de Apache e Mosquitto: replicado do Relatório 04. ) 

**Habilitar serviços (se necessário):**

```bash
# comando: iniciar os serviços (laboratório)
sudo systemctl enable --now apache2
sudo systemctl enable --now mosquitto
```



**Configurar o Mosquitto para aceitar conexões externas (lab):**

```bash
# comando: editar a configuração
sudo nano /etc/mosquitto/mosquitto.conf
```

Adicionar **ao final** do arquivo (linhas novas):

```
listener 1883 0.0.0.0   # aceita conexões de qualquer IP
allow_anonymous true    # sem autenticação (somente para fins didáticos!)
```

Salvar (**Ctrl+X**, **Y**, **Enter**) e aplicar:

```bash
# comando: reiniciar o broker
sudo systemctl restart mosquitto
```

(Configuração e reinício conforme Relatório 04.) 

**Descobrir o IP privado (para a VNet):**

```bash
# comando: ver interfaces e IP
ip a
```

(Anote o **IP privado** da vm1-servidor — usaremos na vm2-cliente.)

### 2) **vm2-cliente** — utilitários de teste

```bash
# comando: atualizar e instalar utilitários de cliente
sudo apt update && sudo apt install -y curl mosquitto-clients
```



---

## VI. Testes práticos (HTTP e MQTT) — Didático e guiado

> **Antes**: mantenha um terminal aberto na **vm1-servidor** com o **tshark** para “ver” os pacotes chegando.

### A) **Monitoramento com tshark (na vm1-servidor)**

```bash
# comando: capturar somente HTTP(80) e MQTT(1883)
sudo tshark -i any -f "tcp port 80 or tcp port 1883"
```

(É a mesma ideia do 04 com filtro por portas 1883/80 — no 04 usam interface enp0s3; na Azure, “any” funciona bem.) 

### B) **HTTP — cliente acessa o servidor**

Na **vm2-cliente**, troque `<IP-privado-vm1>` pelo IP anotado:

```bash
# comando: baixar a página padrão do Apache na vm1-servidor
curl http://<IP-privado-vm1> -s | head
```

(Expectativa no 04: **HTTP 200 OK** no tshark ao acessar a página.) 

> **Explicação didática**: este teste prova **conectividade L3 dentro da VNet** e o serviço **HTTP** ativo na vm1. No **tshark**, você deve ver `GET / HTTP/1.1` seguido de `200 OK`. 

### C) **MQTT — publicação/assinatura entre as VMs**

**Opção 1 (sugestão):** assine na **vm1-servidor** e publique na **vm2-cliente**.

* **vm1-servidor** (assinar o tópico):

```bash
# comando: assinar tópico de teste no broker local
mosquitto_sub -h localhost -t "topico/teste"
```

(Assinatura em terminal: igual ao 04, adaptado de `test/topic`.) 

* **vm2-cliente** (publicar para o IP da vm1):

```bash
# comando: publicar mensagem no broker da vm1-servidor
mosquitto_pub -h <IP-privado-vm1> -t "topico/teste" -m "Olá MQTT na Azure!"
```

(No 04, a publicação remota usa `mosquitto_pub -h <IP-VM1> ...`.) 

> **Explicação didática**: você testou **publish/subscribe** via **broker Mosquitto**. A mensagem deve **aparecer no terminal assinante** e o **tshark** mostrará `CONNECT/CONNACK/PUBLISH`. 

### D) (Opcional) Testar via **IP público** da vm1-servidor

* **HTTP** (precisa de porta 80 liberada — já abrimos na criação):

```bash
curl http://<IP-publico-vm1> -I
```

* **MQTT** (exige **NSG 1883/TCP** já criada na etapa E):

```bash
mosquitto_pub -h <IP-publico-vm1> -t "topico/teste" -m "Teste via Internet"
```

> **Atenção**: `allow_anonymous true` foi usado **só para laboratório** — **não** exponha em produção.

---

## VII. Quadro comparativo (o que cada teste prova)

| Cenário                        | Origem → Destino           | Serviço/Porta | Comando principal                                      | O que comprova                                                   |
| ------------------------------ | -------------------------- | ------------- | ------------------------------------------------------ | ---------------------------------------------------------------- |
| HTTP interno                   | vm2 → vm1 (VNet)           | 80/TCP        | `curl http://<IP-privado-vm1>`                         | Apache recebendo na VNet; rota e NSG internos OK.                |
| MQTT interno (sub no servidor) | vm2 → vm1 (VNet)           | 1883/TCP      | `mosquitto_pub -h <IP-vm1> ...`                        | Broker operante; publish/subscribe funcionando pela VNet.        |
| HTTP público (opcional)        | vm2/local → vm1 (Internet) | 80/TCP        | `curl http://<IP-publico-vm1> -I`                      | NSG liberando 80 na NIC/PIP e Apache acessível pela Internet.    |
| MQTT público (opcional)        | vm2/local → vm1 (Internet) | 1883/TCP      | `mosquitto_pub -h <IP-publico-vm1> ...`                | NSG liberando 1883; broker acessível — **usar só em lab**.       |
| Monitoramento                  | vm1 (tshark)               | 80/1883       | `sudo tshark -i any -f "tcp port 80 or tcp port 1883"` | Visibilidade dos pacotes HTTP/MQTT (GET/200 e CONNECT/PUBLISH).  |

---

## VIII. Evidências rápidas 

```bash
# comando: mostrar interfaces (evidência de IP)
ip a

# comando: serviços rodando
systemctl status apache2 --no-pager -l | sed -n '1,20p'
systemctl status mosquitto --no-pager -l | sed -n '1,20p'

# comando: teste HTTP
curl -I http://<IP-privado-vm1>

# comando: teste MQTT (publicação)
mosquitto_pub -h <IP-privado-vm1> -t "topico/teste" -m "OK"

# comando: 5 primeiros pacotes capturados
sudo timeout 5s tshark -i any -f "tcp port 80 or tcp port 1883" -V | head -n 80
```

---

## IX. Conclusão

Você **migrou** a prática do Relatório 04 para a **Azure**: criou **recursos de rede**, subiu **duas VMs**, habilitou **HTTP e MQTT**, validou **comandos de cliente** e **observou pacotes** com **tshark**. O exercício cobre os objetivos do 04 (Apache + Mosquitto + análise de tráfego), agora **fora do VirtualBox** e **em nuvem pública**. 

---

## Apêndice — **Troubleshooting didático**

**1) Tamanho de VM indisponível / erro de cota**

* Mensagem comum: *“Este tamanho está atualmente indisponível… NotAvailableForSubscription”*.
* Soluções práticas:

  * **Troque a região** (ex.: `West US 2` funcionou).
  * Em **“Selecionar um tamanho de VM”** → **Ver todos os tamanhos** → procure **D2s**; se não houver, selecione **B1ms**.
  * Opcional: clique em **“Pedir quota/Atualizar quota”**.

**2) HTTP abre, mas MQTT não conecta**

* Verifique **NSG** na vm1: precisa de **Regra de entrada TCP 1883** **Permitir**.
* No servidor, confira se o Mosquitto está ouvindo em `0.0.0.0:1883`:

```bash
# comando: verificar escuta do broker
ss -lntp | grep 1883
```

* Revise o arquivo `/etc/mosquitto/mosquitto.conf` e a reinicialização do serviço. 

**3) tshark não captura nada**

* Troque `-i any` por a interface real (geralmente `eth0` na Azure):

```bash
# comando: listar interfaces para o tshark
tshark -D
```

* Reaplique o filtro: `sudo tshark -i eth0 -f "tcp port 80 or tcp port 1883"`. 

**4) HTTP não responde**

* Confirme Apache ativo:

```bash
# comando: status do Apache
systemctl is-active apache2 && sudo ss -lntp | grep :80
```

* Valide no cliente: `curl -v http://<IP-privado-vm1>` (olhe códigos `200`/`301` etc.). 

**5) MQTT sem mensagem no assinante**

* Garanta **um terminal com `mosquitto_sub`** rodando e publique no **mesmo tópico**.
* Repita a publicação com `-d` (debug) para ver handshake:

```bash
# comando: publicar com debug
mosquitto_pub -d -h <IP-privado-vm1> -t "topico/teste" -m "Teste"
```

(Espera-se sequência CONNECT → CONNACK → PUBLISH.) 
