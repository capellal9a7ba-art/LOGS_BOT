FROM python:3.12-slim

# Install system utilities: p7zip-full provides native 7z CLI for RAR5, 7Z, and ZIP extraction
RUN apt-get update && apt-get install -y --no-install-recommends \
    p7zip-full \
    unrar-free \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["python", "bot.py"]
