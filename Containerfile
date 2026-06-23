FROM docker.io/library/golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/muninid ./cmd/muninid
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/muninid-migrate ./cmd/muninid-migrate

FROM docker.io/library/alpine:3.22

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=build /out/muninid /app/muninid
COPY --from=build /out/muninid-migrate /app/muninid-migrate
COPY migrations /app/migrations

EXPOSE 8080

CMD ["/app/muninid"]
