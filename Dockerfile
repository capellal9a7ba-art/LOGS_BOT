FROM python:3.12-slim

# Install system utilities: 7zip, curl, ca-certificates and official RARLAB unrar binary for RAR5 and encrypted archives
RUN apt-get update && apt-get install -y --no-install-recommends \
    p7zip-full \
    curl \
    ca-certificates \
    tar \
    && curl -fsSL https://www.rarlab.com/rar/rarlinux-x64-701.tar.gz -o /tmp/rarlinux.tar.gz \
    && tar -xzf /tmp/rarlinux.tar.gz -C /tmp \
    && cp /tmp/rar/unrar /usr/local/bin/unrar \
    && chmod 755 /usr/local/bin/unrar \
    && rm -rf /tmp/rarlinux.tar.gz /tmp/rar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["python", "bot.py"]
