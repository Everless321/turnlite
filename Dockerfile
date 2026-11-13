FROM golang:1.24-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/turnlite .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/turnlite /turnlite
EXPOSE 3478/udp 3478/tcp 5349/tcp
ENTRYPOINT ["/turnlite"]
