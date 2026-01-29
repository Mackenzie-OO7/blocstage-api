# Build stage
FROM rust:1.84-bookworm as builder

WORKDIR /app

# Copy manifests to build dependencies (for caching)
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY . .

# Build the application
# Touch main.rs to force rebuild of the application code
ENV SQLX_OFFLINE=true
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install necessary runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/blocstage /app/blocstage

# Copy migrations if needed (or run them in build, but typically needed at runtime)
COPY --from=builder /app/migrations /app/migrations

# Create a non-root user
RUN useradd -m appuser && \
    chown -R appuser:appuser /app

USER appuser

# Expose port
expose 8080

# Run the binary
CMD ["./blocstage"]
