FROM node:24 AS build_js
RUN npm install -g @angular/cli@21
COPY frontend ./frontend
RUN cd frontend && npm run build

FROM golang:1.25 AS build_go
COPY go.mod go.sum *.go ./
RUN go build -o /app

FROM debian:13
WORKDIR /app
COPY --from=build_js frontend/dist ./frontend/dist
COPY --from=build_go /app .
CMD [ "./app" ]
