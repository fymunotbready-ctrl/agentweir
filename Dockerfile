# syntax=docker/dockerfile:1
# Stage 1: build from source in a throwaway image and run the self-test.
FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make STATIC=1 && ./agentweir selftest

# Stage 2: small runtime image. Runs as a non-root user.
FROM debian:12-slim
RUN useradd --system --uid 10001 --no-create-home agentweir \
    && mkdir -p /logs /etc/agentweir \
    && chown agentweir /logs
COPY --from=build /src/agentweir /usr/local/bin/agentweir
COPY policy.example.conf /etc/agentweir/policy.conf
USER agentweir
WORKDIR /logs
ENTRYPOINT ["agentweir"]
# Default: run as a proxy. Publish the port on localhost only (see README).
CMD ["proxy", "--policy", "/etc/agentweir/policy.conf", "--log", "/logs/audit.jsonl", "--listen", "0.0.0.0:8899"]
