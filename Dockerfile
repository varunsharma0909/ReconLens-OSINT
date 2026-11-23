FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000 \
    DATABASE_PATH=/app/database/osint.db

WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY . .

# Run as a non-root user; SQLite and log directories must be writable.
RUN groupadd -r reconlens && useradd -r -g reconlens reconlens \
    && mkdir -p /app/database /app/logs \
    && chown -R reconlens:reconlens /app
USER reconlens
EXPOSE 10000
CMD ["sh", "-c", "exec gunicorn 'app:create_app()' --bind 0.0.0.0:${PORT:-10000} --workers 2 --timeout 120"]
