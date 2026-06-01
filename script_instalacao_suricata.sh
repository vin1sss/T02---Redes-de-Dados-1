# AO ABRIR O TERMINAL, EXECUTE ISSO UMA VEZ, NO INICIO:
sudo su

# Siga a execução de todos os comandos abaixo
#!/usr/env bash

# =========================
# detecta versao do Debian
# =========================
CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME")
VERSION_ID=$(. /etc/os-release && echo "$VERSION_ID")
echo "Debian detectado: $VERSION_ID ($CODENAME)"

# =========================
# corrige/reinicia rede
# compatível com Debian 12 e 13
# =========================
# pega interface física principal
IFACE=$(ip -br link show | awk '
$1 !~ /^(lo|docker|veth|br-|virbr|tun|tap)/ {
    gsub("@.*","",$1)
    print $1
    exit
}')
echo "Interface detectada: $IFACE"
# recria configuração de rede limpa
cat > /etc/network/interfaces <<EOF
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

allow-hotplug $IFACE
iface $IFACE inet dhcp
EOF
# para serviços que podem atrapalhar
systemctl stop NetworkManager 2>/dev/null || true
systemctl stop packagekit 2>/dev/null || true
# mata processos DHCP antigos
killall dhclient 2>/dev/null || true
pkill -x packagekitd 2>/dev/null || true
# limpa interface
ip addr flush dev "$IFACE"
ip link set dev "$IFACE" down
ip link set dev "$IFACE" up
echo
echo "=== TENTANDO OBTER IP ==="
# método 1: dhclient
if command -v dhclient >/dev/null 2>&1; then
    echo "[+] usando dhclient"
    dhclient -v "$IFACE"
# método 2: ifup
elif command -v ifup >/dev/null 2>&1; then
    echo "[+] usando ifup"
    ifdown "$IFACE" 2>/dev/null || true
    ifup "$IFACE"
# método 3: networkctl
elif command -v networkctl >/dev/null 2>&1; then
    echo "[+] usando networkctl/systemd-networkd"
    systemctl restart systemd-networkd
    networkctl renew "$IFACE" 2>/dev/null || true
# fallback final
else
    echo "[!] nenhum cliente DHCP encontrado"
    echo "[!] tentando reiniciar systemd-networkd"
    systemctl restart systemd-networkd || true
fi
sleep 3
echo
echo "=== STATUS DA REDE ==="
ip -br address show "$IFACE"
ip route

# =========================
# Instalar suricata.
# corrige pacotes quebrados,
# remove listas antigas,
# verifica instalacao
# =========================
dpkg --configure -a
# remove listas antigas/problemáticas
# cuidado fora do laboratório
rm -f /etc/apt/sources.list.d/*
# adiciona backports corretos
echo "deb http://deb.debian.org/debian $CODENAME-backports main" \
> "/etc/apt/sources.list.d/$CODENAME-backports.list"
# atualiza pacotes
apt update
# instala suricata
apt install -y -t "$CODENAME-backports" suricata suricata-update
# instala dependências úteis
apt install -y dnsutils net-tools curl wget tcpdump jq
# verifica instalação
echo
echo "=== VERSAO SURICATA ==="
suricata -V

# esperado:
# This is Suricata version 7.x RELEASE
