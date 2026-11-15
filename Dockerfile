# syntax=docker/dockerfile:1
# Stage 1: build from source in a throwaway image and run the self-test.
FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make STATIC=1 && ./agentwall selftest

# Stage 2: small runtime image. Runs as a non-root user.
FROM debian:12-slim
RUN useradd --system --uid 10001 --no-create-home agentwall \
    && mkdir -p /logs /etc/agentwall \
    && chown agentwall /logs
COPY --from=build /src/agentwall /usr/local/bin/agentwall
COPY policy.example.conf /etc/agentwall/policy.conf
USER agentwall
WORKDIR /logs
ENTRYPOINT ["agentwall"]
# Default: run as a proxy. Publish the port on localhost only (see README).
CMD ["proxy", "--policy", "/etc/agentwall/policy.conf", "--log", "/logs/audit.jsonl", "--listen", "0.0.0.0:8899"]
