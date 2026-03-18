FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY config/ config/
COPY static/ static/
COPY db/ db/
COPY docker/nmap-scripts/ docker/nmap-scripts/

RUN mkdir -p /usr/share/nmap/scripts/custom && \
    cp docker/nmap-scripts/*.nse /usr/share/nmap/scripts/custom/ && \
    nmap --script-updatedb || true

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
