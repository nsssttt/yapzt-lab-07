FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=8787 \
    APP_DB=/data/taskboard.sqlite3

WORKDIR /app
COPY app.py /app/app.py
RUN useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data
USER appuser
EXPOSE 8787
CMD ["python", "/app/app.py"]
