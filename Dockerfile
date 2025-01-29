FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

ADD . .

# Install package dependencies
RUN uv sync

ENTRYPOINT ["uv", "run", "--directory", "src", "python", "-m", "unittest", "discover", "-v", "-s", "tests"]