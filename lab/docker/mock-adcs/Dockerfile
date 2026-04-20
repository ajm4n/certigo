# syntax=docker/dockerfile:1.6

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mock-adcs main.go

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/mock-adcs /mock-adcs
EXPOSE 8080 8443
ENTRYPOINT ["/mock-adcs"]
