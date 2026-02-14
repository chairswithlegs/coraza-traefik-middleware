package audit

import (
	"github.com/corazawaf/coraza/v3/types"
)

type Log struct {
	Transaction Transaction `json:"transaction"`
	Messages    []Message   `json:"messages,omitempty"`
}

type Message struct {
	Message string      `json:"message"`
	Data    MessageData `json:"data"`
}

type MessageData struct {
	File     string             `json:"file"`
	Line     int                `json:"line"`
	ID       int                `json:"id"`
	Rev      string             `json:"rev"`
	Msg      string             `json:"msg"`
	Data     string             `json:"data"`
	Severity types.RuleSeverity `json:"severity"`
	Ver      string             `json:"ver"`
	Maturity int                `json:"maturity"`
	Accuracy int                `json:"accuracy"`
	Tags     []string           `json:"tags"`
	Raw      string             `json:"raw"`
}

type Transaction struct {
	// Timestamp "02/Jan/2006:15:04:20 -0700" format
	Timestamp     string               `json:"timestamp"`
	UnixTimestamp int64                `json:"unix_timestamp"`
	ID            string               `json:"id"`
	ClientIP      string               `json:"client_ip"`
	ClientPort    int                  `json:"client_port"`
	HostIP        string               `json:"host_ip"`
	HostPort      int                  `json:"host_port"`
	ServerID      string               `json:"server_id"`
	Request       *TransactionRequest  `json:"request,omitempty"`
	Response      *TransactionResponse `json:"response,omitempty"`
}

type TransactionRequest struct {
	Method      string              `json:"method"`
	Protocol    string              `json:"protocol"`
	URI         string              `json:"uri"`
	HTTPVersion string              `json:"http_version"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
}

type TransactionResponse struct {
	Protocol string              `json:"protocol"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	Body     string              `json:"body"`
}
