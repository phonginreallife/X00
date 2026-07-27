// Package logging provides the level filtering behind the monitoring.logLevel
// setting.
//
// KernelSeal emits one event per exec on a busy host, which drowns out the lines
// that matter, so per-event tracing belongs at debug while lifecycle and security
// events stay visible by default.
package logging

import (
	"fmt"
	"log"
	"strings"
	"sync/atomic"
)

// Level is a log verbosity threshold.
type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// current is read on every log call, so it is stored atomically rather than
// behind a mutex.
//
// It is initialized explicitly because the zero value of atomic.Int32 is 0,
// which is LevelDebug: without this, anything logged before SetLevel runs would
// default to the noisiest level rather than the safest one.
var current atomic.Int32

func init() { SetLevel(LevelInfo) }

// Parse converts a configured level name into a Level.
func Parse(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "info", "": // empty means unset, so take the default
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level %q: want debug, info, warn or error", s)
	}
}

// SetLevel sets the minimum level that will be emitted.
func SetLevel(l Level) { current.Store(int32(l)) }

// GetLevel reports the current threshold.
func GetLevel() Level { return Level(current.Load()) }

// Enabled reports whether a level would be emitted. Useful for skipping
// expensive formatting.
func Enabled(l Level) bool { return l >= GetLevel() }

func emit(l Level, format string, args ...any) {
	if !Enabled(l) {
		return
	}
	log.Printf(format, args...)
}

// Debugf logs per-event detail, off by default.
func Debugf(format string, args ...any) { emit(LevelDebug, format, args...) }

// Infof logs lifecycle and security events.
func Infof(format string, args ...any) { emit(LevelInfo, format, args...) }

// Warnf logs conditions that degrade protection.
func Warnf(format string, args ...any) { emit(LevelWarn, format, args...) }

// Errorf logs failures.
func Errorf(format string, args ...any) { emit(LevelError, format, args...) }
