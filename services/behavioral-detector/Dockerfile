FROM python:3.11-slim

# Install Poetry
RUN pip install --no-cache-dir poetry

WORKDIR /app

# Copy dependency manifests first (better layer caching)
COPY pyproject.toml poetry.lock* ./

# Install dependencies (no virtualenv inside the container - install into system env)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

# Copy the rest of the source
COPY . .

# Install the local package itself now that source is present
RUN poetry install --no-interaction --no-ansi

# Long-running loop (not one-shot like canary-validator/ml-trainer): no
# EXPOSE, no server -- see app/main.py's scan loop. No HTTP /health either
# (unlike isolation-forest), so liveness is a heartbeat file touched once per
# loop iteration -- healthy as long as it's fresher than 3 scan intervals
# (default: 180s), which tolerates one slow/failed tick without flapping.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,sys,time; p=os.getenv('HEARTBEAT_FILE','/tmp/behavioral-detector-heartbeat'); m=int(os.getenv('SCAN_INTERVAL_SECONDS','60'))*3; sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p)<m else 1)"]

CMD ["poetry", "run", "python", "-m", "app.main"]
