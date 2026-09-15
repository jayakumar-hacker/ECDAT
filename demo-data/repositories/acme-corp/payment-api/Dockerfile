FROM python:3.11-slim

RUN apt-get update && apt-get install -y openssl libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ ./src/

EXPOSE 8443
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "key.pem", "--ssl-certfile", "cert.pem"]
