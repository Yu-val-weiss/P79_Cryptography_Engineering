FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY . .

# Install package dependencies
RUN uv sync

ENTRYPOINT ["uv", "run", "python", "-m", "pytest"]
