FROM alpine:3.20 as prep

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
# ! Adjust the binary name to match the name of the binary that is built
# In case of a Go binary, the binary name is the project name defined in
# your .goreleaser.yml configuration file
COPY meta ./

USER appuser

ENTRYPOINT ["/meta"]