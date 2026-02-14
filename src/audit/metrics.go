package audit

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var metricAuditLogTransactionsCount = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "audit_log_transactions",
		Help: "The total number of audit log transactions processed",
	},
	[]string{"status_code", "method", "host", "path"},
)

func sendTransactionMetrics(log Log) {
	request := log.Transaction.Request
	response := log.Transaction.Response

	statusCode := "unknown"
	if response != nil {
		statusCode = strconv.Itoa(response.Status)
	}

	method := "unknown"
	host := "unknown"
	path := "unknown"
	if request != nil {
		method = request.Method
		uri, err := url.Parse(request.URI)
		if err == nil {
			host = uri.Host
			path = uri.Path
		}
	}
	metricAuditLogTransactionsCount.WithLabelValues(statusCode, method, host, path).Inc()
}

var metricAuditLogRuleViolations = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "audit_log_rule_violations",
		Help: "The total number of audit log rule violations",
	},
	[]string{"rule_id", "method", "host", "path"},
)

func sendRuleViolationMetrics(log Log) {
	request := log.Transaction.Request

	method := "unknown"
	host := "unknown"
	path := "unknown"
	if request != nil {
		method = request.Method
		uri, err := url.Parse(request.URI)
		if err == nil {
			host = uri.Host
			path = uri.Path
		}
	}

	for _, msg := range log.Messages {
		ruleID := fmt.Sprintf("%s-%d", msg.Data.File, msg.Data.ID)
		metricAuditLogRuleViolations.WithLabelValues(ruleID, method, host, path).Inc()
	}
}
