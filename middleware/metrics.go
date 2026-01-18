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
			Buckets: prometheus.DefBuckets,
		},
		[]string{requestMethod, requestPath, statusCode},
	)
)

func init() {
	prometheus.MustRegister(requestCounter, requestLatency)
}

func MetricHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		start := time.Now()
		ctx.Next()
		duration := time.Since(start)
		httpStatusCode := strconv.Itoa(ctx.Writer.Status())
		if strings.HasPrefix(httpStatusCode, "4") || strings.HasPrefix(httpStatusCode, "5") {
			slog.DebugContext(ctx, fmt.Sprintf("Request failed with status code %s for %s at %s from %s", httpStatusCode, ctx.Request.Method, ctx.FullPath(), ctx.Request.Host))
		}
		requestCounter.With(
			prometheus.Labels{
				requestMethod: ctx.Request.Method,
				requestPath:   ctx.FullPath(),
				statusCode:    httpStatusCode,
			},
		).Inc()
		requestLatency.WithLabelValues(ctx.Request.Method, ctx.FullPath(), httpStatusCode).
			Observe(duration.Seconds())
	}
}
