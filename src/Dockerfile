FROM golang:1.25 AS build_go
COPY go.mod go.sum *.go *.sql ./
RUN go build -o /app

FROM debian:13
WORKDIR /app
COPY --from=build_go /app .
CMD [ "./app" ]
