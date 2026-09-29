FROM alpine:3.24 AS builder
WORKDIR /src
RUN apk add --no-cache bash git nodejs npm
COPY . .
RUN bash scripts/build.alpine.release.sh

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /src/subconverter/ /base/
WORKDIR /base
ENV TZ=Etc/UTC
EXPOSE 25500/tcp
CMD ["/base/subconverter"]
