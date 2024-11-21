### Step 1: Build stage
FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o jwt-revoker

## Step 2: Runtime stage
FROM scratch

COPY --from=builder /app/jwt-revoker /
COPY ./static /static

ENTRYPOINT ["/jwt-revoker", "-server", "krakend_ce:1234"]
