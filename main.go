package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/dparrish/go-autoconfig"
	"github.com/olivere/elastic/v7"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
)

var (
	configFile = flag.String("config", "config.yaml", "Path to configuration file")

	elasticClient *elastic.Client
)

const (
	dateFormat = "2006-01-02T15:04:05.999Z07:00"
)

type ipMatch struct {
	ip       net.IP
	count    int
	banned   time.Time
	lastSeen time.Time
}

type RootBlocker struct {
	sync.RWMutex

	e       *elastic.Client
	router  *EdgeRouter
	config  *autoconfig.Config
	match   *regexp.Regexp
	indices []string
	ips     map[string]*ipMatch
}

func (r *RootBlocker) runQuery(ctx context.Context, lastTimestamp time.Time) (*elastic.SearchResult, error) {
	r.RLock()
	defer r.RUnlock()

	boolQuery := elastic.NewBoolQuery().Filter(
		elastic.NewQueryStringQuery(fmt.Sprintf("message: %q", r.config.Get("elasticsearch.match"))),
		elastic.NewBoolQuery().Filter(elastic.NewRangeQuery("@timestamp").Gte(lastTimestamp.Add(1*time.Millisecond).Format(dateFormat))),
	)

	ctx, searchSpan := trace.StartSpan(ctx, fmt.Sprintf("rootblocker elasticsearch Search"))
	defer searchSpan.End()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res, err := r.e.Search().Index(r.indices...).Sort("@timestamp", true).Query(boolQuery).From(0).Size(100).Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("Error in query: %v", err)
	}

	stats.Record(ctx, metrics.MessagesPerSearch.M(int64(len(res.Hits.Hits))))
	return res, err
}

func (r *RootBlocker) tail(ctx context.Context) error {
	lastTimestamp := time.Now()
	for {
		checkDuration, err := time.ParseDuration(r.config.Get("elasticsearch.check_frequency"))
		if err != nil {
			log.Warningf("elasticsearch.check_frequency is invalid, defaulting to 1s")
			checkDuration = time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(checkDuration):
		}

		func() {
			ctx, span := trace.StartSpan(ctx, fmt.Sprintf("rootblocker tail"))
			defer span.End()

			res, err := r.runQuery(ctx, lastTimestamp)
			if err != nil {
				log.Error(err)
				return
			}
			if len(res.Hits.Hits) == 0 {
				return
			}

			for _, hit := range res.Hits.Hits {
				var entry map[string]interface{}
				if err := json.Unmarshal(hit.Source, &entry); err != nil {
					log.Errorf("Error unmarshalling hit: %v", err)
					continue
				}
				ts, err := time.Parse(dateFormat, entry["@timestamp"].(string))
				if err != nil {
					log.Errorf("Error parsing timestamp %q: %v", entry["@timestamp"].(string), err)
					continue
				}
				lastTimestamp = ts
				msg := entry["message"].(string)
				log.Debugf("%s", msg)
				m := r.match.FindStringSubmatch(msg)
				if len(m) != 2 {
					log.Warningf("No IP address found in message %q", msg)
					continue
				}

				ip := net.ParseIP(m[1])
				r.RLock()
				i, ok := r.ips[ip.String()]
				r.RUnlock()

				if ok {
					log.Infof("Found existing IP %s", ip)
					i.lastSeen = ts
					i.count++
					if !i.banned.IsZero() && time.Since(i.banned) > 1*time.Minute {
						log.Errorf("IP %s continues to be seen after being banned %s ago", i.ip, time.Since(i.banned))
					}
				} else {
					r.Lock()
					r.ips[ip.String()] = &ipMatch{
						ip:       ip,
						count:    1,
						lastSeen: ts,
					}
					log.Infof("Found new IP %s, there are now %d IPs in the ban list", ip, len(r.ips))
					r.Unlock()
				}
			}
			log.Infof("Processed %d messages", len(res.Hits.Hits))
			metrics.MessagesProcessed.Inc(int64(len(res.Hits.Hits)))
			r.updateBans(ctx)
		}()
	}
}

func (r *RootBlocker) removeOld(ctx context.Context) {
	timeout, err := time.ParseDuration(r.config.Get("timeout"))
	if err != nil {
		log.Errorf("Invalid timeout %q: %v", r.config.Get("timeout"), err)
		return
	}
	r.Lock()
	defer r.Unlock()
	if len(r.ips) == 0 {
		return
	}
	_, searchSpan := trace.StartSpan(ctx, fmt.Sprintf("rootblocker removeOld"))
	defer searchSpan.End()

	log.Debugf("Removing bans older than %s (from %d total)", timeout, len(r.ips))
	for _, i := range r.ips {
		if time.Since(i.lastSeen) < timeout {
			continue
		}
		if i.banned.IsZero() {
			continue
		}
		log.Infof("%s has not been seen in %s, removing from ban list", i.ip.String(), time.Since(i.lastSeen))
		delete(r.ips, i.ip.String())
	}
}

func (r *RootBlocker) updateBans(ctx context.Context) {
	r.Lock()
	defer r.Unlock()
	log.Debugf("Updating bans")
	var banned, count, updates int64

	for _, i := range r.ips {
		ip := i.ip.String()

		count++
		if !i.banned.IsZero() {
			log.Debugf("%s is already banned", ip)
			banned++
			continue
		}
		if i.count < r.config.GetInt("threshold") {
			log.Debugf("%s has only been seen %d times (<%d)", ip, i.count, r.config.GetInt("threshold"))
			continue
		}
		log.Infof("%s has been seen %d times, banning", ip, i.count)

		_, searchSpan := trace.StartSpan(ctx, fmt.Sprintf("rootblocker updateBan"))
		defer searchSpan.End()
		if updates == 0 {
			if err := r.router.Connect(ctx); err != nil {
				log.Fatalf("Error connecting to router: %v", err)
			}
			defer r.router.Close()
		}
		updates++
		i.banned = time.Now()
		if err := r.router.AddIP(ctx, ip); err != nil {
			log.Fatalf("Error banning %q: %v", ip, err)
		}
	}
	metrics.BanListBans.Set(banned)
	metrics.BanListCount.Set(count)

	if updates > 0 {
		if err := r.router.Commit(ctx); err != nil {
			log.Fatalf("Error commiting configuration: %v", err)
		}
	}
}

func (r *RootBlocker) run(ctx context.Context) {
	r.indices = r.selectIndices(r.config.Get("elasticsearch.index"))
	if len(r.indices) == 0 {
		log.Fatalf("Invalid initial configuration, no indices match %q", r.config.Get("elasticsearch.index"))
	}
	var err error
	r.match, err = regexp.Compile(r.config.Get("elasticsearch.match"))
	if err != nil {
		log.Fatal("Invalid initial match regexp: %v", err)
	}

	r.config.AddValidator(func(old, new *autoconfig.Config) error {
		r.Lock()
		defer r.Unlock()
		if old.Get("elasticsearch.index") != new.Get("elasticsearch.index") {
			i := r.selectIndices(new.Get("elasticsearch.index"))
			if len(i) == 0 {
				return fmt.Errorf("No indices match %q", new.Get("elasticsearch.index"))
			}
			log.Debugf("Using indices: %v", i)
			r.indices = i
		}
		if old.Get("elasticsearch.match") != new.Get("elasticsearch.match") {
			re, err := regexp.Compile(new.Get("elasticsearch.match"))
			if err != nil {
				return fmt.Errorf("Invalid match regexp %q: %v", new.Get("elasticsearch.match"), err)
			}
			r.match = re
		}
		return nil
	})
	log.Debugf("Using %d indices: %v", len(r.indices), r.indices)

	if err := r.router.Connect(ctx); err != nil {
		log.Fatalf("Error connecting to router: %v", err)
	}
	if err := r.router.Clear(ctx); err != nil {
		log.Fatalf("Error clearing ruleset: %v", err)
	}
	if err := r.router.Commit(ctx); err != nil {
		log.Fatalf("Error commiting configuration: %v", err)
	}
	r.router.Close()

	go r.tail(ctx)

	removeOldTicker := time.NewTicker(30 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return
		case <-removeOldTicker.C:
			r.removeOld(ctx)
		}
	}
}

func (r *RootBlocker) selectIndices(pattern string) []string {
	indices, err := r.e.IndexNames()
	if err != nil {
		log.Fatalf("Could not fetch available indices: %v", err)
	}

	index := findLastIndex(indices, pattern)
	var results []string
	for _, i := range []string{index} {
		if i != "" {
			results = append(results, i)
		}
	}
	return results
}

func findLastIndex(indices []string, indexPattern string) string {
	var lastIdx string
	for _, idx := range indices {
		matched, _ := regexp.MatchString(indexPattern, idx)
		if matched {
			if &lastIdx == nil {
				lastIdx = idx
			} else if idx > lastIdx {
				lastIdx = idx
			}
		}
	}
	return lastIdx
}

func main() {
	flag.Parse()
	//log.SetReportCaller(true)

	// Load the configuration.
	config := autoconfig.New(*configFile)
	config.Required("elasticsearch.url")
	config.Required("elasticsearch.index")
	config.Required("elasticsearch.match")
	config.Required("threshold")
	config.Default("timeout", "1h")
	config.Default("elasticsearch.check_frequency", "1s")

	if err := config.Load(); err != nil {
		log.Fatal(err)
	}
	if err := config.Watch(context.Background()); err != nil {
		log.Fatal(err)
	}

	client, err := elastic.NewSimpleClient(elastic.SetURL(config.Get("elasticsearch.url")))
	if err != nil {
		log.Fatal("Can't create elastic client: %v", err)
	}

	createMetrics(config)

	r := &RootBlocker{
		e:      client,
		config: config,
		ips:    make(map[string]*ipMatch),
		router: &EdgeRouter{
			config: config,
		},
	}
	go r.run(context.Background())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Infof("Listening on %s", port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}
