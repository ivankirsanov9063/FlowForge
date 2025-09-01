FROM archlinux:latest AS builder

# Обновляем систему и устанавливаем необходимые пакеты
RUN pacman -Syu --noconfirm && pacman -S --noconfirm base-devel cmake git pkgconf libnl nftables boost sudo iproute2 jq srt

RUN pacman -S --noconfirm python python-pip && pip install requests --break-system-packages

WORKDIR /app

CMD ["python3", "docker.py", "main", "client", "Client"]