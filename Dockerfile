# syntax=docker/dockerfile:1.6

# ---------- Frontend build stage ----------
FROM node:20-bookworm-slim AS frontend-builder
WORKDIR /build/frontend

COPY fortress-lens-main/package*.json ./
RUN npm ci

COPY fortress-lens-main/ ./
RUN npm run build


# ---------- Python dependency build stage ----------
FROM python:3.11-slim AS python-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/backend
COPY requirements.txt ./

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ---------- Backend runtime target ----------
FROM python:3.11-slim AS backend-runtime
ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY --from=python-builder /opt/venv /opt/venv

# Copy only runtime backend files (no frontend source)
COPY main.py alembic.ini backend_topology.py ./
COPY api ./api
COPY app ./app
COPY database ./database
COPY collectors ./collectors
COPY config ./config
COPY migrations ./migrations
COPY alembic ./alembic
COPY parsers ./parsers
COPY services ./services
COPY utils ./utils

RUN mkdir -p /app/data

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]


# ---------- Frontend runtime target ----------
FROM nginx:alpine AS frontend-runtime

COPY --from=frontend-builder /build/frontend/dist /srv/frontend
COPY docker/nginx.frontend.conf /etc/nginx/conf.d/default.conf

EXPOSE 8501
CMD ["nginx", "-g", "daemon off;"]


# ---------- All-in-one runtime target (single container) ----------
FROM python:3.11-slim AS all-in-one-runtime
ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=python-builder /opt/venv /opt/venv

COPY main.py alembic.ini backend_topology.py ./
COPY api ./api
COPY app ./app
COPY database ./database
COPY collectors ./collectors
COPY config ./config
COPY migrations ./migrations
COPY alembic ./alembic
COPY parsers ./parsers
COPY services ./services
COPY utils ./utils

COPY --from=frontend-builder /build/frontend/dist /srv/frontend
COPY docker/nginx.local.conf /etc/nginx/conf.d/default.conf
COPY START.sh /app/start.sh

RUN mkdir -p /app/data \
    && chmod +x /app/start.sh

EXPOSE 8000 8501
ENTRYPOINT ["/app/start.sh"]
