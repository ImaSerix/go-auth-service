# Auth service image. Targets:
#   docker build .                   -> service image (default, last stage)
#   docker build --target migrate .  -> one-shot migrations image (golang-migrate)

# ---- build stage ----
FROM golang:1.25.14-alpine3.24 AS build
WORKDIR /src

# Download dependencies first so this layer is cached until go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth ./cmd/server

# ---- migrations image ----
# Runs `migrate` against migrations/postgres; the database URL and the
# migrator role credentials are passed at run time, never baked into the image.
FROM migrate/migrate:v4.20.1 AS migrate
COPY migrations/postgres /migrations
ENTRYPOINT ["migrate", "-path", "/migrations"]
CMD ["-help"]

# ---- runtime stage (default target) ----
FROM alpine:3.24.4
# Unprivileged service user named after the service (D-19).
RUN adduser -D -H -s /sbin/nologin auth
COPY --from=build /out/auth /usr/local/bin/auth
EXPOSE 8080
USER auth
# All configuration comes from environment variables (see README).
ENTRYPOINT ["/usr/local/bin/auth"]
