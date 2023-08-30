FROM golang:alpine as builder

RUN apk update && apk add --no-cache git build-base
COPY . /HFP

WORKDIR /HFP
RUN go mod tidy
RUN go build -ldflags "-s -w" -o HFP *.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /HFP/HFP .

ENTRYPOINT ["/root/HFP"]
