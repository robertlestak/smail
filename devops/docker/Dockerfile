FROM golang:1.18 as builder

ARG VERSION

WORKDIR /src

COPY . .

RUN go build -ldflags="-X 'main.Version=$VERSION'" -o /bin/smail cmd/smail/*.go

FROM debian:bullseye as runtime

RUN apt-get update -y && apt-get install -y ca-certificates

COPY --from=builder /bin/smail /bin/smail

ENTRYPOINT [ "/bin/smail" ]