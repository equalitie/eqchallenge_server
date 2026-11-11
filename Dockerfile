# Demo of pkg/codechallenge (cmd/demo). Not a production image: in production banjax links
# the package in.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /demo ./cmd/demo

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /demo /demo
EXPOSE 8080
ENTRYPOINT ["/demo"]
