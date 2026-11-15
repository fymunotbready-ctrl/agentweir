# syntax=docker/dockerfile:1
# Stage 1: build from source in a throwaway image and run the self-test.
FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make STATIC=1 && ./agentweil selftest

# Stage 2: small runtime image. Runs as a non-root user.
FROM debian:12-slim
RUN useradd --system --uid 10001 --no-create-home agentweil \
    && mkdir -p /logs /etc/agentweil \
    && chown agentweil /logs
COPY --from=build /src/agentweil /usr/local/bin/agentweil
COPY policy.example.conf /etc/agentweil/policy.conf
USER agentweil
WORKDIR /logs
ENTRYPOINT ["agentweil"]
# Default: run as a proxy. Publish the port on localhost only (see README).
CMD ["proxy", "--policy", "/etc/agentweil/policy.conf", "--log", "/logs/audit.jsonl", "--listen", "0.0.0.0:8899"]
