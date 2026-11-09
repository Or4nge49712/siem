#!/usr/bin/env bash
# Préparation de la VM Linux SIEM (Ubuntu Server 22.04/24.04) - à lancer en root : sudo bash setup-siem.sh
# Proxmox : cartes ens18/ens19 (par défaut).  VirtualBox : sudo WAN_IF=enp0s3 LAN_IF=enp0s8 bash setup-siem.sh
# Fait : fuseau horaire + NTP, paquets de base, vm.max_map_count, Docker + Compose, routage NAT du lab.
set -euo pipefail

WAN_IF="${WAN_IF:-ens18}"        # carte sur le VLAN admin (Internet)
LAN_IF="${LAN_IF:-ens19}"        # carte sur le VLAN lab
LAB_NET="${LAB_NET:-10.10.10.0/24}"

echo "[1/5] Heure et paquets de base"
timedatectl set-timezone Europe/Paris
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
apt-get install -y chrony curl jq git python3-pip iptables-persistent
systemctl enable --now chrony
# Agent invité Proxmox uniquement (inutile et sans effet sous VirtualBox)
if [ "$(systemd-detect-virt)" = "kvm" ]; then
  apt-get install -y qemu-guest-agent
  systemctl enable --now qemu-guest-agent || true
fi

echo "[2/5] Réglage noyau requis par Elasticsearch"
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elastic.conf
echo "net.ipv4.ip_forward=1"   > /etc/sysctl.d/99-lab-routing.conf
sysctl --system >/dev/null

echo "[3/5] Docker Engine + Compose"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
if [ -n "${SUDO_USER:-}" ]; then usermod -aG docker "$SUDO_USER"; fi

echo "[4/5] NAT : la VM Windows sort sur Internet via cette VM"
iptables -t nat -C POSTROUTING -s "$LAB_NET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$LAB_NET" -o "$WAN_IF" -j MASQUERADE
# Docker passe la politique FORWARD à DROP : on autorise explicitement le trafic du lab dans DOCKER-USER
iptables -C DOCKER-USER -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT 2>/dev/null \
  || iptables -I DOCKER-USER -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
iptables -C DOCKER-USER -i "$WAN_IF" -o "$LAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
  || iptables -I DOCKER-USER -i "$WAN_IF" -o "$LAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
netfilter-persistent save

echo "[5/5] Vérifications"
docker --version
docker compose version
sysctl vm.max_map_count net.ipv4.ip_forward
ip -br addr
echo "OK. Déconnectez-vous puis reconnectez-vous pour utiliser docker sans sudo."
