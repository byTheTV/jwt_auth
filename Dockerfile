# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /auth-service ./src/main.go

# Final stage
FROM alpine:3.18
WORKDIR /app
COPY --from=builder /auth-service .
COPY config.yaml .

EXPOSE 8080
CMD ["./auth-service"]