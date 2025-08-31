FROM debian:latest AS builder

RUN apt-get update && apt-get install -y libsystemd-dev build-essential cmake git pkg-config libnl-3-dev libnl-route-3-dev libnftables-dev libboost-all-dev sudo iproute2 jq libsrt-openssl-dev

RUN apt install python3 pip -y && pip install requests --break-system-packages

WORKDIR /app

COPY /dockers/docker.py /app/docker.py

#python3 docker.py <ветка> <режим> <файл который нужно запускать>
CMD ["python3", "docker.py", "main", "client", "Client"]