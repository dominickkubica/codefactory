FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o /app ./cmd/app

FROM gcr.io/distroless/static
COPY --from=build /app /app
USER nonroot
ENTRYPOINT ["/app"]
