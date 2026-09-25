package observability

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Metrics struct {
	HTTPRequests *prometheus.CounterVec
	HTTPLatency  *prometheus.HistogramVec
	HTTPInflight prometheus.Gauge
	HTTPErrors   *prometheus.CounterVec
	GRPCRequests *prometheus.CounterVec
	GRPCLatency  *prometheus.HistogramVec
	GRPCErrors   *prometheus.CounterVec
}

func NewMetrics(registry prometheus.Registerer) *Metrics {
	m := &Metrics{
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "identity_http_requests_total", Help: "Total HTTP requests."}, []string{"method", "route", "status_class"}),
		HTTPLatency:  prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "identity_http_request_duration_seconds", Help: "HTTP request duration in seconds.", Buckets: prometheus.DefBuckets}, []string{"method", "route"}),
		HTTPInflight: prometheus.NewGauge(prometheus.GaugeOpts{Name: "identity_http_requests_in_flight", Help: "Current HTTP requests in flight."}),
		HTTPErrors:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "identity_http_errors_total", Help: "Total HTTP responses with error status codes."}, []string{"method", "route", "status_class"}),
		GRPCRequests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "identity_grpc_requests_total", Help: "Total gRPC requests."}, []string{"service", "method", "status"}),
		GRPCLatency:  prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "identity_grpc_request_duration_seconds", Help: "gRPC request duration in seconds.", Buckets: prometheus.DefBuckets}, []string{"service", "method"}),
		GRPCErrors:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "identity_grpc_errors_total", Help: "Total gRPC requests returning an error."}, []string{"service", "method", "status"}),
	}
	for _, collector := range []prometheus.Collector{m.HTTPRequests, m.HTTPLatency, m.HTTPInflight, m.HTTPErrors, m.GRPCRequests, m.GRPCLatency, m.GRPCErrors} {
		registry.MustRegister(collector)
	}
	return m
}

func (m *Metrics) GinMiddleware(c *gin.Context) {
	m.HTTPInflight.Inc()
	defer m.HTTPInflight.Dec()
	started := time.Now()
	c.Next()
	route := c.FullPath()
	if route == "" {
		route = "unmatched"
	}
	statusClass := strconv.Itoa(c.Writer.Status()/100) + "xx"
	m.HTTPRequests.WithLabelValues(c.Request.Method, route, statusClass).Inc()
	m.HTTPLatency.WithLabelValues(c.Request.Method, route).Observe(time.Since(started).Seconds())
	if c.Writer.Status() >= 400 {
		m.HTTPErrors.WithLabelValues(c.Request.Method, route, statusClass).Inc()
	}
}

func (m *Metrics) Handler() gin.HandlerFunc { return gin.WrapH(promhttp.Handler()) }

func (m *Metrics) UnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	started := time.Now()
	response, err := handler(ctx, req)
	m.observeGRPC(info.FullMethod, status.Code(err), time.Since(started))
	return response, err
}

func (m *Metrics) StreamServerInterceptor(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	started := time.Now()
	err := handler(srv, stream)
	m.observeGRPC(info.FullMethod, status.Code(err), time.Since(started))
	return err
}

func (m *Metrics) observeGRPC(fullMethod string, code codes.Code, elapsed time.Duration) {
	parts := strings.Split(strings.TrimPrefix(fullMethod, "/"), "/")
	service, method := "unknown", "unknown"
	if len(parts) == 2 {
		service, method = parts[0], parts[1]
	}
	statusName := code.String()
	m.GRPCRequests.WithLabelValues(service, method, statusName).Inc()
	m.GRPCLatency.WithLabelValues(service, method).Observe(elapsed.Seconds())
	if code != codes.OK {
		m.GRPCErrors.WithLabelValues(service, method, statusName).Inc()
	}
}

func BuildInfo(version, commit, buildDate string) prometheus.Collector {
	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "identity_build_info", Help: "Identity service build metadata."}, []string{"version", "commit", "build_date"})
	info.WithLabelValues(version, commit, buildDate).Set(1)
	return info
}

func Metadata(version, commit, buildDate string) string {
	return fmt.Sprintf("version=%s commit=%s build_date=%s", version, commit, buildDate)
}
