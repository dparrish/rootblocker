package main

import (
	"net/http"
	"time"

	"contrib.go.opencensus.io/exporter/prometheus"
	"contrib.go.opencensus.io/exporter/stackdriver"
	"github.com/dparrish/go-autoconfig"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/metric"
	"go.opencensus.io/metric/metricproducer"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/trace"
)

var metrics struct {
	MessagesProcessed *metric.Int64CumulativeEntry
	MessagesPerSearch *stats.Int64Measure
	BanListCount      *metric.Int64GaugeEntry
	BanListBans       *metric.Int64GaugeEntry
}

func createMetrics(config *autoconfig.Config) {
	if config.GetRaw("stackdriver_project") != nil {
		// Export to Stackdriver Monitoring.
		sdExporter, err := stackdriver.NewExporter(stackdriver.Options{ProjectID: config.Get("stackdriver_project")})
		if err != nil {
			log.Fatal(err)
		}

		// Export to Stackdriver.
		trace.RegisterExporter(sdExporter)
		trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})
	}

	// Export prometheus style metrics
	exporter, err := prometheus.NewExporter(prometheus.Options{})
	if err != nil {
		log.Fatal(err)
	}
	view.RegisterExporter(exporter)
	view.SetReportingPeriod(5 * time.Second)
	http.Handle("/metrics", exporter)

	registry := metric.NewRegistry()
	metricproducer.GlobalManager().AddProducer(registry)

	g, err := registry.AddInt64Gauge("rootblocker/ban_list/size", metric.WithDescription("Number of IPs being tracked"))
	if err != nil {
		log.Fatal(err)
	}
	metrics.BanListCount, err = g.GetEntry()
	if err != nil {
		log.Fatal(err)
	}

	g, err = registry.AddInt64Gauge("rootblocker/ban_list/bans", metric.WithDescription("Number of IPs that are currently banned"))
	if err != nil {
		log.Fatal(err)
	}
	metrics.BanListBans, err = g.GetEntry()
	if err != nil {
		log.Fatal(err)
	}

	cg, err := registry.AddInt64Cumulative("rootblocker/messages_processed", metric.WithDescription("Total number of log messages processed"))
	if err != nil {
		log.Fatal(err)
	}
	metrics.MessagesProcessed, err = cg.GetEntry()
	if err != nil {
		log.Fatal(err)
	}

	metrics.MessagesPerSearch = stats.Int64("rootblocker/messages_per_search", "Number of messages processed per Elasticsearch Search operation", "")
	view.Register(&view.View{
		Name:        metrics.MessagesPerSearch.Name(),
		Description: metrics.MessagesPerSearch.Description(),
		Measure:     metrics.MessagesPerSearch,
		Aggregation: view.Distribution(0, 2<<0, 2<<1, 2<<2, 2<<3, 2<<4, 2<<5, 2<<6, 2<<7, 2<<8, 2<<9, 2<<10),
	})

}
