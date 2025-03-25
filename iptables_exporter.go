// Copyright 2018 RetailNext, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Obmondo/iptables_exporter/iptables"
	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
)

type (
	collector struct{}

	pageData struct {
		MetricsPath string
	}
)

var (
	scrapeDurationDesc = prometheus.NewDesc(
		"iptables_scrape_duration_seconds",
		"iptables_exporter: Duration of scraping iptables.",
		nil,
		nil,
	)

	scrapeSuccessDesc = prometheus.NewDesc(
		"iptables_scrape_success",
		"iptables_exporter: Whether scraping iptables succeeded.",
		nil,
		nil,
	)

	defaultBytesDesc = prometheus.NewDesc(
		"iptables_default_bytes_total",
		"iptables_exporter: Total bytes matching a chain's default policy.",
		[]string{"table", "chain", "policy"},
		nil,
	)

	defaultPacketsDesc = prometheus.NewDesc(
		"iptables_default_packets_total",
		"iptables_exporter: Total packets matching a chain's default policy.",
		[]string{"table", "chain", "policy"},
		nil,
	)

	ruleBytesDesc = prometheus.NewDesc(
		"iptables_rule_bytes_total",
		"iptables_exporter: Total bytes matching a rule.",
		[]string{"table", "chain", "rule"},
		nil,
	)

	rulePacketsDesc = prometheus.NewDesc(
		"iptables_rule_packets_total",
		"iptables_exporter: Total packets matching a rule.",
		[]string{"table", "chain", "rule"},
		nil,
	)
)

func (c *collector) Describe(descChan chan<- *prometheus.Desc) {
	descChan <- scrapeDurationDesc
	descChan <- scrapeSuccessDesc
	descChan <- defaultBytesDesc
	descChan <- defaultPacketsDesc
	descChan <- ruleBytesDesc
	descChan <- rulePacketsDesc
}

func (c *collector) Collect(metricChan chan<- prometheus.Metric) {
	start := time.Now()
	tables, err := iptables.GetTables()
	duration := time.Since(start)

	metricChan <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, duration.Seconds())
	if err != nil {
		metricChan <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, 0)
		slog.Error("failed during metric collection", slog.String("err", err.Error()))
		return
	}

	metricChan <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, 1)

	for tableName, table := range tables {
		for chainName, chain := range table {
			metricChan <- prometheus.MustNewConstMetric(
				defaultPacketsDesc,
				prometheus.CounterValue,
				float64(chain.Packets),
				tableName,
				chainName,
				chain.Policy,
			)
			metricChan <- prometheus.MustNewConstMetric(
				defaultBytesDesc,
				prometheus.CounterValue,
				float64(chain.Bytes),
				tableName,
				chainName,
				chain.Policy,
			)
			for _, rule := range chain.Rules {
				metricChan <- prometheus.MustNewConstMetric(
					rulePacketsDesc,
					prometheus.CounterValue,
					float64(rule.Packets),
					tableName,
					chainName,
					rule.Rule,
				)
				metricChan <- prometheus.MustNewConstMetric(
					ruleBytesDesc,
					prometheus.CounterValue,
					float64(rule.Bytes),
					tableName,
					chainName,
					rule.Rule,
				)
			}
		}
	}
}

func main() {
	// Adapted from github.com/prometheus/node_exporter

	var (
		listenAddress = kingpin.Flag("web.listen-address", "Address on which to expose metrics and web interface.").Default(":9455").String()
		metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	)

	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.Version(version.Print("iptables_exporter"))
	kingpin.CommandLine.UsageWriter(os.Stderr)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := promslog.New(promslogConfig)
	slog.SetDefault(logger)

	slog.Info("Starting iptables_exporter", slog.String("version", version.Info()))
	slog.Info("Build information", slog.String("build_context", version.BuildContext()))

	c := collector{}
	prometheus.MustRegister(&c)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := pageData{
			MetricsPath: *metricsPath,
		}

		tmpl := `
		<html>
			<head><title>iptables exporter</title></head>
			<body>
				<h1>iptables exporter</h1>
				<p><a href="{{ .MetricsPath }}">Metrics</a></p>
			</body>
		</html>`

		t, err := template.New("homePage").Parse(tmpl)
		if err != nil {
			http.Error(w, "Error parsing template", http.StatusInternalServerError)
			return
		}

		if err := t.Execute(w, data); err != nil {
			http.Error(w, "Error rendering template", http.StatusInternalServerError)
		}
	})

	slog.Info("Listening on", slog.String("listen_address", *listenAddress))
	err := http.ListenAndServe(*listenAddress, nil)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("failed during server shutdown", slog.String("err", err.Error()))
		os.Exit(1)
	}
}
