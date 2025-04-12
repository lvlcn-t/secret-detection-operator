FROM alpine:3.21 AS prep

RUN apk add --no-cache ca-certificates
RUN adduser \
    --disabled-password \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid 65532 \
    appuser


FROM scratch
COPY --from=prep /etc/passwd /etc/passwd
COPY --from=prep /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY secret-detection-operator ./

USER appuser

ENTRYPOINT ["/secret-detection-operator"]