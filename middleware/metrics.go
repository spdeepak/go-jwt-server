package middleware

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	requestMethod = "requestMethod"
	requestPath   = "requestPath"
	statusCode    = "statusCode"
)

var (
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "go_jwt_server_api_request_counter",
			Help: "API request counter",
		}, []string{requestMethod, requestPath, statusCode},
	)
	requestLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "go_jwt_server_api_latency_milliseconds",
			Help:    "API request latency",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
		},
		[]string{requestMethod, requestPath, statusCode},
	)
	inFlightRequests = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "go_jwt_server_api_in_flight_requests",
			Help: "Current number of in-flight HTTP requests",
		},
		[]string{requestPath},
	)
	requestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "go_jwt_server_api_request_size_bytes",
			Help:    "HTTP request size",
			Buckets: prometheus.ExponentialBuckets(200, 2, 8),
		},
		[]string{requestMethod, requestPath},
	)
	responseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "go_jwt_server_api_response_size_bytes",
			Help:    "HTTP response size",
			Buckets: prometheus.ExponentialBuckets(200, 2, 8),
		},
		[]string{requestMethod, requestPath, statusCode},
	)
)

func init() {
	prometheus.MustRegister(requestCounter, requestLatency, inFlightRequests, requestSize, responseSize)
}

func MetricHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		path := ctx.FullPath()
		inFlightRequests.WithLabelValues(path).Inc()
		if ctx.Request.ContentLength > 0 {
			requestSize.WithLabelValues(ctx.Request.Method, path).Observe(float64(ctx.Request.ContentLength))
		}
		start := time.Now()
		ctx.Next()
		duration := time.Since(start)
		httpStatusCode := strconv.Itoa(ctx.Writer.Status())
		if strings.HasPrefix(httpStatusCode, "4") || strings.HasPrefix(httpStatusCode, "5") {
			slog.DebugContext(ctx, fmt.Sprintf("Request failed with status code %s for %s at %s from %s", httpStatusCode, ctx.Request.Method, path, ctx.Request.Host))
		}
		requestCounter.WithLabelValues(ctx.Request.Method, path, httpStatusCode).Inc()
		requestLatency.WithLabelValues(ctx.Request.Method, path, httpStatusCode).Observe(float64(duration.Milliseconds()))
		responseSize.WithLabelValues(ctx.Request.Method, path, httpStatusCode).Observe(float64(ctx.Writer.Size()))
		inFlightRequests.WithLabelValues(path).Dec()
	}
}
