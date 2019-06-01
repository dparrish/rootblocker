FROM golang:1.12 as builder

WORKDIR /go/src
ENV GO111MODULE=on
RUN go get contrib.go.opencensus.io/exporter/prometheus contrib.go.opencensus.io/exporter/stackdriver github.com/dparrish/go-autoconfig github.com/google/goexpect github.com/olivere/elastic/v7 github.com/sirupsen/logrus golang.org/x/crypto/ssh go.opencensus.io/metric go.opencensus.io/metric/metricproducer go.opencensus.io/stats go.opencensus.io/stats/view go.opencensus.io/trace golang.org/x/crypto
COPY *.go go.mod go.sum ./
RUN go get .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo
RUN strip rootblocker

FROM phusion/baseimage:latest
ENV GOOGLE_APPLICATION_CREDENTIALS=/tmp/credentials.json
COPY --from=builder /go/src/rootblocker /app/
CMD ["/app/rootblocker"]
