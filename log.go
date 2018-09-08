package log

import (
	"io"
	"io/ioutil"
	"os"

	"net/http"

	"net"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	Logger *logrus.Logger
}

type Loggable interface {
	LogData() map[string]interface{}
}

type logEntry struct {
	entry *logrus.Entry
}

type LogType string

type entryLoggerFunc func(e *logEntry, logger *Logger, arg interface{}) (*logEntry, bool)

var (
	serverIP   string
	serverName string

	debugLog  *Logger
	errLog    *Logger
	infoLog   *Logger
	warnLog   *Logger
	fatalLog  *Logger
	panicLog  *Logger
	accessLog *Logger
	syslog    *Logger
)

func init() {
	serverIP = externalIP()
	serverName, _ = os.Hostname()

	debugLog = &Logger{Logger: logrus.New()}
	debugLog.Logger.SetLevel(logrus.DebugLevel)
	debugLog.Logger.Formatter = &logrus.TextFormatter{}
	debugLog.Logger.Out = ioutil.Discard

	accessLog = &Logger{Logger: logrus.New()}
	accessLog.Logger.SetLevel(logrus.InfoLevel)
	accessLog.Logger.Formatter = &logrus.JSONFormatter{}
	accessLog.Logger.Out = os.Stdout

	infoLog = &Logger{Logger: logrus.New()}
	infoLog.Logger.SetLevel(logrus.InfoLevel)
	infoLog.Logger.Formatter = &logrus.JSONFormatter{}
	infoLog.Logger.Out = os.Stdout

	warnLog = &Logger{Logger: logrus.New()}
	warnLog.Logger.SetLevel(logrus.WarnLevel)
	warnLog.Logger.Formatter = &logrus.JSONFormatter{}
	warnLog.Logger.Out = os.Stdout

	errLog = &Logger{Logger: logrus.New()}
	errLog.Logger.SetLevel(logrus.ErrorLevel)
	errLog.Logger.Formatter = &logrus.JSONFormatter{}
	errLog.Logger.Out = os.Stderr

	fatalLog = &Logger{Logger: logrus.New()}
	fatalLog.Logger.SetLevel(logrus.FatalLevel)
	fatalLog.Logger.Formatter = &logrus.JSONFormatter{}
	fatalLog.Logger.Out = os.Stderr

	panicLog = &Logger{Logger: logrus.New()}
	panicLog.Logger.SetLevel(logrus.PanicLevel)
	panicLog.Logger.Formatter = &logrus.JSONFormatter{}
	panicLog.Logger.Out = os.Stderr

	syslog = &Logger{Logger: logrus.New()}
	syslog.Logger.SetLevel(logrus.InfoLevel)
	syslog.Logger.Formatter = &logrus.JSONFormatter{}
	syslog.Logger.Out = os.Stdout
}

func SetAccess(format logrus.Formatter, output io.Writer) {
	setLogger(accessLog, format, output)
}

func SetDebug(format logrus.Formatter, output io.Writer) {
	setLogger(debugLog, format, output)
}

func SetInfo(format logrus.Formatter, output io.Writer) {
	setLogger(infoLog, format, output)
}

func SetWarn(format logrus.Formatter, output io.Writer) {
	setLogger(warnLog, format, output)
}

func SetError(format logrus.Formatter, output io.Writer) {
	setLogger(errLog, format, output)
}

func SetFatal(format logrus.Formatter, output io.Writer) {
	setLogger(fatalLog, format, output)
}

func SetPanic(format logrus.Formatter, output io.Writer) {
	setLogger(panicLog, format, output)
}

func SetSystem(format logrus.Formatter, output io.Writer) {
	setLogger(syslog, format, output)
}

func setLogger(logger *Logger, formatter logrus.Formatter, output io.Writer) {
	logger.Logger.Formatter = formatter
	logger.Logger.Out = output
}

func Access(args ...interface{}) {
	accessLog.Log(append(args, LogType("access"))...)
}

func Debug(args ...interface{}) {
	debugLog.Log(append(args, LogType("debug"))...)
}

func Info(args ...interface{}) {
	infoLog.Log(append(args, LogType("info"))...)
}

func Warn(args ...interface{}) {
	warnLog.Log(append(args, LogType("warning"))...)
}

func Error(args ...interface{}) {
	errLog.Log(append(args, LogType("error"))...)
}

func Fatal(args ...interface{}) {
	fatalLog.Log(append(args, LogType("fatal"))...)
}

func Panic(args ...interface{}) {
	panicLog.Log(append(args, LogType("panic"))...)
}

func System(args ...interface{}) {
	syslog.Log(append(args, LogType("system"))...)
}

func (l *Logger) Log(args ...interface{}) {
	var unknownArgs []interface{}

	var entry *logEntry

	for _, arg := range args {
		entry = entry.logEntries(l, arg, logTypeEntry, loggableEntry, requestEntry, mapEntry, errorEntry)

		if entry == nil {
			unknownArgs = append(unknownArgs, arg)
		}
	}

	entry = hostEntry(entry, l)
	entry.entry.Println(unknownArgs...)
}

func (e *logEntry) logEntries(logger *Logger, arg interface{}, logEntryFuncs ...entryLoggerFunc) *logEntry {
	for _, f := range logEntryFuncs {
		e, ok := f(e, logger, arg)
		if ok {
			return e
		}
	}

	return e
}

func logTypeEntry(e *logEntry, logger *Logger, arg interface{}) (*logEntry, bool) {
	logType, ok := arg.(LogType)
	if ok {
		if e == nil {
			e = &logEntry{entry: logger.Logger.WithField("log_type", logType)}
		} else {
			e.entry = e.entry.WithField("log_type", logType)
		}
	}

	return e, ok
}

func loggableEntry(e *logEntry, logger *Logger, arg interface{}) (*logEntry, bool) {
	loggable, ok := arg.(Loggable)
	if ok {
		if e == nil {
			e = &logEntry{logger.Logger.WithFields(loggable.LogData())}
		} else {
			e.entry = e.entry.WithFields(loggable.LogData())
		}
	}

	return e, ok
}

func errorEntry(e *logEntry, logger *Logger, arg interface{}) (*logEntry, bool) {
	err, ok := arg.(error)
	if ok {
		if e == nil {
			e = &logEntry{logger.Logger.WithField("error", err.Error())}
		} else {
			e.entry = e.entry.WithField("error", err.Error())
		}
	}

	return e, ok
}

func requestEntry(e *logEntry, logger *Logger, arg interface{}) (*logEntry, bool) {
	request, ok := arg.(*http.Request)
	if ok {
		fields := logrus.Fields{
			"request.target":           request.URL.Path,
			"request.query":            request.URL.RawQuery,
			"request.ip":               request.RemoteAddr,
			"request.x-forwarded-for":  request.Header.Get("X-Forwarded-For"),
			"request.x-forwarded-host": request.Header.Get("X-Forwarded-Host"),
			"request.origin":           request.Header.Get("Origin"),
			"request.method":           request.Method,
			"request.proto":            request.Proto,
			"request.user_agent":       request.UserAgent(),
		}

		if e == nil {
			e = &logEntry{logger.Logger.WithFields(fields)}
		} else {
			e.entry = e.entry.WithFields(fields)
		}
	}

	return e, ok
}

func mapEntry(e *logEntry, logger *Logger, arg interface{}) (*logEntry, bool) {
	mapped, ok := arg.(map[string]interface{})
	if ok {
		if e == nil {
			e = &logEntry{logger.Logger.WithFields(mapped)}
		} else {
			e.entry = e.entry.WithFields(mapped)
		}
	}

	return e, ok
}

func hostEntry(e *logEntry, logger *Logger) *logEntry {
	if e == nil {
		e = &logEntry{logger.Logger.WithField("host.name", serverName)}
	} else {
		e.entry = e.entry.WithField("host.name", serverName)
	}

	if serverIP != "" {
		e.entry = e.entry.WithField("host.ip", serverIP)
	}

	return e
}

func externalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return ""
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String()
		}
	}

	return ""
}
