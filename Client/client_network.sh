#!/usr/bin/env bash
set -euo pipefail

SERVER_IP="${1:-193.233.23.221}"
TUN="${2:-cvpn0}"

# Поднять TUN и адреса (v4 + v6 p2p)
sudo ip link set "$TUN" up
sudo ip addr flush dev "$TUN"
sudo ip addr add 10.8.0.2/32 peer 10.8.0.1 dev "$TUN"
sudo ip -6 addr add fd00:dead:beef::2/128 peer fd00:dead:beef::1 dev "$TUN" 2>/dev/null || true
sudo ip link set dev "$TUN" mtu 1400

# Прямой маршрут до сервера (чтобы трафик к серверу не ушёл в тоннель)
# IPv4 default
GW4="$(ip -4 route show default | awk '/default/ {print $3; exit}')"
# IPv6 default
GW6="$(ip -6 route show default | awk '/default/ {print $3; exit}')"
DEV6="$(ip -6 route show default | awk '/default/ {print $5; exit}')"

if [[ "$SERVER_IP" == *:* ]]; then
  # Сервер по IPv6
  if [[ -n "${GW6:-}" && -n "${DEV6:-}" ]]; then
    sudo ip -6 route add "${SERVER_IP}/128" via "$GW6" dev "$DEV6" 2>/dev/null || true
  fi
else
  # Сервер по IPv4
  if [[ -n "${GW4:-}" ]]; then
    sudo ip route add "${SERVER_IP}/32" via "$GW4" 2>/dev/null || true
  fi
fi

# Дефолтные маршруты в туннель
sudo ip route replace default dev "$TUN"
sudo ip -6 route replace default dev "$TUN" 2>/dev/null || true

# Включить форвардинг (на всякий случай для локальных сервисов)
sudo sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
