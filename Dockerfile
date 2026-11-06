# The gateway and tenantctl in one small image.
#
#   docker build -t mdm-gateway .
#
# Built static, run as an unprivileged user. Nothing secret is baked in: the
# platform keys and database logins arrive as environment variables at start
# and entrypoint.sh moves the keys out of the environment (see there).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateway   ./cmd/gateway \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tenantctl ./cmd/tenantctl

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 10001 mdm \
 && mkdir -p /dev/shm/mdm-secrets && chown mdm /dev/shm/mdm-secrets
COPY --from=build /out/gateway /out/tenantctl /usr/local/bin/
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
USER mdm
ENV MDM_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["gateway"]
