FROM python:3.11-slim

# System deps sometimes needed for scikit-learn / numpy wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

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

# One-shot job: no EXPOSE, no server. Runs once and exits.
CMD ["poetry", "run", "python", "-m", "app.main"]
