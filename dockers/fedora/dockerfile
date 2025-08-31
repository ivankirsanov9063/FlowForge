FROM fedora:latest AS builder

RUN dnf -y update && dnf -y install gcc-c++ make cmake git wget pkgconfig libnl3-devel nftables-devel boost-devel sudo curl iproute jq srt-devel systemd-devel

RUN dnf install -y python3 pip && pip install requests

WORKDIR /app

COPY /dockers/docker.py /app/docker.py

#python3 docker.py <ветка> <режим> <файл который нужно запускать>
CMD ["python3", "docker.py", "main", "client", "Client"]