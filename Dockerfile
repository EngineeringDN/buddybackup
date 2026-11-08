# All FROM references are immutable. restic's extracted linux/amd64 executable
# is checked again below. This image currently targets amd64 TrueNAS hosts.
FROM --platform=linux/amd64 restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510 AS restic
FROM --platform=linux/amd64 golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG BUILD_TAGS=
RUN --mount=type=cache,id=buddybackup-go,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags "ts_omit_peerapiserver,ts_omit_webclient,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,$BUILD_TAGS" -ldflags='-s -w' -o /out/buddybackup .
COPY --from=restic /usr/bin/restic /out/restic
RUN echo '20d4142678d0d95ec11a4759def1b73fd9190abc9ca19e4b62d067c0b387e639  /out/restic' | sha256sum -c -
FROM --platform=linux/amd64 alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
# No package installation: CA trust comes from the pinned Go build image.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/buddybackup /usr/bin/buddybackup
COPY --from=build /out/restic /usr/bin/restic
USER 0:0
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/buddybackup"]
