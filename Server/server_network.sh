#!/usr/bin/env bash
set -euo pipefail

TUN="${1:-svpn0}"

# Поднимаем TUN и задаём p2p адреса (IPv4 + IPv6)
sudo ip link set "$TUN" up
sudo ip addr flush dev "$TUN"
sudo ip addr add 10.8.0.1/32 peer 10.8.0.2 dev "$TUN"
sudo ip -6 addr add fd00:dead:beef::1/128 peer fd00:dead:beef::2 dev "$TUN" 2>/dev/null || true
sudo ip link set dev "$TUN" mtu 1400

# Включаем форвардинг
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
echo 1 | sudo tee /proc/sys/net/ipv6/conf/all/forwarding >/dev/null

# Определяем внешние интерфейсы для v4 и v6
WAN4="$(ip -o -4 route show to default | awk '{print $5; exit}')"
WAN6="$(ip -o -6 route show to default | awk '{print $5; exit}')"

# NAT44 (если нужен): маскируем исходящий трафик клиентов
sudo nft add table ip nat 2>/dev/null || true
sudo nft 'add chain ip nat POSTROUTING { type nat hook postrouting priority 100 ; }' 2>/dev/null || true
if [[ -n "${WAN4:-}" ]]; then
  sudo nft add rule ip nat POSTROUTING oif "$WAN4" ip saddr 10.8.0.0/24 counter masquerade 2>/dev/null || true
fi

# NAT66 (если нужен): не обязателен для IPv6, но оставим как у тебя
sudo nft add table ip6 nat 2>/dev/null || true
sudo nft 'add chain ip6 nat POSTROUTING { type nat hook postrouting priority 100 ; }' 2>/dev/null || true
if [[ -n "${WAN6:-}" ]]; then
  sudo nft add rule ip6 nat POSTROUTING oif "$WAN6" ip6 saddr fd00:dead:beef::/64 counter masquerade 2>/dev/null || true
fi

# (Опционально) FIREWALL: открыть порт сервера (UDP) — настроить самостоятельно, если есть фильтры
# sudo nft add rule inet filter input udp dport 5555 accept
