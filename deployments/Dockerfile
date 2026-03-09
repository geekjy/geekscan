# ============ Build Go binaries ============
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /bin/api ./cmd/api
RUN CGO_ENABLED=0 go build -o /bin/worker ./cmd/worker
RUN CGO_ENABLED=0 go build -o /bin/cli ./cmd/cli

# ============ Build Frontend ============
FROM node:20-alpine AS frontend-builder

WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# ============ API Server ============
FROM alpine:3.19 AS api

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/api /usr/local/bin/api
COPY configs/ /app/configs/
COPY dictionaries/ /app/dictionaries/

WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["api", "-config", "/app/configs/config.yaml"]

# ============ Worker ============
FROM alpine:3.19 AS worker

RUN apk add --no-cache ca-certificates tzdata chromium

# Download rad binary (Linux amd64)
ADD https://github.com/chaitin/rad/releases/download/1.0/rad_linux_amd64.zip /tmp/rad.zip
RUN unzip /tmp/rad.zip -d /usr/local/bin/ && chmod +x /usr/local/bin/rad && rm /tmp/rad.zip || true

COPY --from=builder /bin/worker /usr/local/bin/worker
COPY configs/ /app/configs/
COPY dictionaries/ /app/dictionaries/

WORKDIR /app
ENTRYPOINT ["worker", "-config", "/app/configs/config.yaml"]

# ============ Frontend (Nginx) ============
FROM nginx:alpine AS frontend

COPY --from=frontend-builder /web/dist /usr/share/nginx/html
COPY deployments/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
