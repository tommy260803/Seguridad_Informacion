FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiar todo el código (incluyendo src/) antes de instalar
COPY . .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -e .

# Exponer el puerto
EXPOSE 8000

# Ejecutar el servidor con uvicorn
CMD ["uvicorn", "phishguard_api.server:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
