# Runs the harness in a container. The environment itself is simulated in-process;
# the container just isolates the run and pins dependencies.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY control_harness ./control_harness
RUN pip install --no-cache-dir .
ENTRYPOINT ["python", "-m", "control_harness"]
