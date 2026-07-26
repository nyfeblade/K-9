# K-9 — zero-dependency LAN scanner.
# Build:  docker build -t k9 .
# Run:    docker run --rm -it --net host k9         # dashboard on :8731
#         docker run --rm -it --net host k9 --cli   # one-shot terminal report
#
# IMPORTANT: --net host is required. K-9 discovers devices via ARP/ping on the
# host's LAN; a bridged container is on its own private docker network and would see
# nothing. With --net host the dashboard is reachable at http://localhost:8731.
FROM python:3.12-slim

# The only things K-9 shells out to: `ip` (iproute2), `ping` (iputils-ping),
# and optionally `nmap` — which also ships the 42k-entry MAC-vendor DB at
# /usr/share/nmap/nmap-mac-prefixes that K-9 reads for vendor identification.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Data (scope, engagement, known devices, dashboard config) lives here — mount a
# volume on it to persist across runs:  -v k9-data:/data
ENV K9_HOME=/data
VOLUME ["/data"]

EXPOSE 8731

# Bind 0.0.0.0 inside the container so the host can reach the dashboard. (Outside a
# container the default stays loopback-only — this override is container-specific.)
ENTRYPOINT ["python3", "k9.py"]
CMD ["--web", "--bind", "0.0.0.0"]
