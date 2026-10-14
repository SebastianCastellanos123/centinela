# Compilar
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/centinela ./cmd/centinela

# Imagen final mínima y sin privilegios
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/centinela /centinela
ENTRYPOINT ["/centinela"]
