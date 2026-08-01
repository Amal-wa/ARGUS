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
# EXPOSE, no server -- see app/main.py's scan loop.
CMD ["poetry", "run", "python", "-m", "app.main"]
