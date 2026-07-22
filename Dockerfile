FROM python:3.8-slim
WORKDIR /usr/src/app
COPY openapi ./openapi
COPY requirements.txt .
COPY vAPI.py .
COPY vAPI.db .

# Aggiunto zlib1g-dev alle dipendenze di sistema
RUN apt-get update && apt-get install -y gcc libxml2-dev libxslt-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8081
CMD [ "python", "./vAPI.py" ]