package auditLog

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/firekitz/fk-lib-iam-go/ctxauth"
	amqp "github.com/rabbitmq/amqp091-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"path"
	"strconv"
	"strings"
	"time"
)

type AMQPConfig struct {
	Server   string
	Username string
	Password string
	Exchange string
	Port     string
}

type FKConfig struct {
	DomainId    int
	ProjectId   int
	ServiceName string
}

type Audit struct {
	LogType        string  `json:"logType"`
	Message        message `json:"message"`
	DomainId       int     `json:"domainId"`
	SrcDomainId    int     `json:"srcDomainId"`
	ServiceName    string  `json:"serviceName"`
	SrcServiceName string  `json:"srcServiceName"`
	ProjectId      int     `json:"projectId"`
	SrcProjectId   int     `json:"srcProjectId"`
	UserId         int     `json:"userId"`
	UserType       int     `json:"userType"`
	ObjectTypeId   int     `json:"objectTypeId"`
	Action         string  `json:"action"`
	OsEnv          string  `json:"osEnv"`
}

type message struct {
	Request  request  `json:"request"`
	Response response `json:"response"`
}

type request struct {
	Method    string `json:"method"`
	Url       string `json:"url"`
	UrlRoute  string `json:"url_route"`
	Query     string `json:"query"`
	Headers   string `json:"headers"`
	Timestamp string `json:"timestamp"`
	Ip        string `json:"ip"`
	Body      string `json:"body"`
}

type response struct {
	StatusCode int    `json:"status_code"`
	Timestamp  string `json:"timestamp"`
	Elapsed    int    `json:"elapsed"`
	Body       string `json:"body"`
}

var ch *amqp.Channel
var MQ_EXCHANGE_AUDIT_LOG = "audit.log.send.direct"
var osEnv string
var fkConfig FKConfig

func Init(amqpConfig AMQPConfig, _fkConfig FKConfig, env string) error {
	osEnv = env
	conn, err := amqp.Dial("amqp://" + amqpConfig.Username + ":" + amqpConfig.Password + "@" +
		amqpConfig.Server + ":" + amqpConfig.Port)
	if err != nil {
		return err
	}
	ch, err = conn.Channel()
	if err != nil {
		return err
	}

	fkConfig = _fkConfig
	return nil
}

func log(message Audit) error {
	m, err := json.Marshal(message)
	if err != nil {
		return err
	}
	err = ch.Publish(
		MQ_EXCHANGE_AUDIT_LOG,
		"",    // routing key
		false, // mandatory
		false, // immediate
		amqp.Publishing{
			ContentType: "application/json",
			Body:        m,
		})
	if err != nil {
		return err
	}
	return nil
}

type ErrorToCode func(err error) codes.Code

type DurationToField func(duration time.Duration) (key string, value interface{})

func FuncErrorToCode(err error) codes.Code {
	return status.Code(err)
}

var DefaultErrorToCode ErrorToCode = FuncErrorToCode

// DefaultDurationToField is the default implementation of converting request duration to a log field (key and value).
var DefaultDurationToField DurationToField = DurationToTimeMillisField

// DurationToTimeMillisField converts the duration to milliseconds and uses the key `grpc.time_ms`.
func DurationToTimeMillisField(duration time.Duration) (key string, value interface{}) {
	return "grpc.time_ms", durationToMilliseconds(duration)
}

// DurationToDurationField uses the duration value to log the request duration.
func DurationToDurationField(duration time.Duration) (key string, value interface{}) {
	return "grpc.duration", duration
}

func durationToMilliseconds(duration time.Duration) float32 {
	return float32(duration.Nanoseconds()/1000) / 1000
}

func AuditServerUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		startMs := time.Now().UnixMilli()
		service := path.Dir(info.FullMethod)[1:]
		method := path.Base(info.FullMethod)

		resp, handlerError := handler(ctx, req)
		code := DefaultErrorToCode(handlerError)
		_, durVal := DefaultDurationToField(time.Since(startTime))
		endMs := time.Now().UnixMilli()

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.DataLoss, "failed to get metadata")
		}
		clientIp := ""
		xForwardFor := md.Get("x-forwarded-for")
		if len(xForwardFor) > 0 && xForwardFor[0] != "" {
			ips := strings.Split(xForwardFor[0], ",")
			if len(ips) > 0 {
				clientIp = ips[0]
			}
		}
		str := fmt.Sprintf("%v", durVal)
		elapsed, _ := strconv.Atoi(str)

		header, err := json.Marshal(md)
		var auditLog Audit

		_auth := ctxauth.Extract(ctx)
		auth := _auth.Values()

		var srcDomainId = 100
		if _auth.Has("auth.domainId") {
			srcDomainId = int(auth["auth.domainId"].(int64))
		}
		var srcProjectId = 5
		if _auth.Has("auth.projectId") {
			srcProjectId = int(auth["auth.projectId"].(int64))
		}
		var accountId = 2
		if _auth.Has("auth.accountId") {
			accountId = int(auth["auth.accountId"].(int64))
		}
		var accountType = 1
		if _auth.Has("auth.accountType") {
			accountType = int(auth["auth.accountType"].(int64))
		}

		auditLog.LogType = "api"
		auditLog.DomainId = fkConfig.DomainId
		auditLog.SrcDomainId = srcDomainId
		auditLog.ServiceName = fkConfig.ServiceName
		auditLog.ProjectId = fkConfig.ProjectId
		auditLog.SrcProjectId = srcProjectId
		auditLog.UserId = accountId
		auditLog.UserType = accountType
		auditLog.ObjectTypeId = 0
		auditLog.Action = "request"
		auditLog.OsEnv = osEnv

		auditLog.Message.Request.UrlRoute = method
		auditLog.Message.Request.Method = service
		auditLog.Message.Request.Timestamp = strconv.FormatInt(startMs, 10)
		auditLog.Message.Request.Ip = clientIp
		auditLog.Message.Request.Headers = string(header)
		auditLog.Message.Request.Body = JSONFormatter(fmt.Sprintf("%v", req))

		auditLog.Message.Response.Elapsed = elapsed
		auditLog.Message.Response.StatusCode = int(code)
		auditLog.Message.Response.Timestamp = strconv.FormatInt(endMs, 10)
		auditLog.Message.Response.Body = JSONFormatter(fmt.Sprintf("%v", resp))

		if err = log(auditLog); err != nil {
			return nil, err
		}

		return resp, handlerError
	}
}

func JSONFormatter(payload string) string {
	if payload = "{" + payload + "}"; payload == "{}" {
		return payload
	}
	json := strings.Replace(payload, " ", ",\"", -1)
	json = strings.Replace(json, "{", "{\"", -1)
	json = strings.Replace(json, ":", "\":", -1)
	return json
}
