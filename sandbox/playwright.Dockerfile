FROM mcr.microsoft.com/playwright/python:v1.42.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Instalar dependencias fijas a la versión de la imagen
RUN pip install playwright==1.42.0

COPY sandbox/playwright_worker.py /app/playwright_worker.py

USER pwuser
ENTRYPOINT ["python", "/app/playwright_worker.py"]
