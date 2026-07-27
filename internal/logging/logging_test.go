package logging

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// captureLog redirects the standard logger for the duration of a test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	flags := log.Flags()
	out := log.Writer()

	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(out)
		log.SetFlags(flags)
	})

	return &buf
}

// withLevel sets the threshold and restores it afterwards, since it is global.
func withLevel(t *testing.T, l Level) {
	t.Helper()

	previous := GetLevel()
	SetLevel(l)
	t.Cleanup(func() { SetLevel(previous) })
}

func TestParse(t *testing.T) {
	tests := []struct {
		input   string
		want    Level
		wantErr bool
	}{
		{"debug", LevelDebug, false},
		{"DEBUG", LevelDebug, false},
		{"  info  ", LevelInfo, false},
		{"", LevelInfo, false}, // unset falls back to the default
		{"warn", LevelWarn, false},
		{"warning", LevelWarn, false},
		{"error", LevelError, false},
		{"verbose", LevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// An unparsable level must still yield a usable default rather than silence.
func TestParse_InvalidReturnsInfo(t *testing.T) {
	got, err := Parse("nonsense")
	if err == nil {
		t.Fatal("expected an error for an unknown level")
	}
	if got != LevelInfo {
		t.Errorf("Parse returned %v on error, want LevelInfo", got)
	}
}

func TestLevel_String(t *testing.T) {
	tests := map[Level]string{
		LevelDebug: "debug",
		LevelInfo:  "info",
		LevelWarn:  "warn",
		LevelError: "error",
		Level(99):  "unknown",
	}
	for level, want := range tests {
		if got := level.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", level, got, want)
		}
	}
}

func TestEnabled(t *testing.T) {
	withLevel(t, LevelWarn)

	if Enabled(LevelDebug) {
		t.Error("debug should be disabled at the warn threshold")
	}
	if Enabled(LevelInfo) {
		t.Error("info should be disabled at the warn threshold")
	}
	if !Enabled(LevelWarn) {
		t.Error("warn should be enabled at the warn threshold")
	}
	if !Enabled(LevelError) {
		t.Error("error should be enabled at the warn threshold")
	}
}

// The flood of per-exec lines that motivated this package must disappear at the
// default level and reappear at debug.
func TestDebugf_SuppressedAtInfo(t *testing.T) {
	withLevel(t, LevelInfo)
	buf := captureLog(t)

	Debugf("[EXEC] PID=%d", 1234)

	if buf.Len() != 0 {
		t.Errorf("Debugf emitted %q at the info threshold", buf.String())
	}
}

func TestDebugf_EmittedAtDebug(t *testing.T) {
	withLevel(t, LevelDebug)
	buf := captureLog(t)

	Debugf("[EXEC] PID=%d", 1234)

	if !strings.Contains(buf.String(), "[EXEC] PID=1234") {
		t.Errorf("Debugf output = %q, want it to contain the formatted message", buf.String())
	}
}

// Security-relevant lines must survive at the default level.
func TestWarnf_EmittedAtInfo(t *testing.T) {
	withLevel(t, LevelInfo)
	buf := captureLog(t)

	Warnf("[LSM BLOCKED] PID=%d", 99)

	if !strings.Contains(buf.String(), "[LSM BLOCKED] PID=99") {
		t.Errorf("Warnf output = %q, want the message", buf.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	tests := []struct {
		threshold Level
		wantInfo  bool
		wantWarn  bool
		wantError bool
	}{
		{LevelDebug, true, true, true},
		{LevelInfo, true, true, true},
		{LevelWarn, false, true, true},
		{LevelError, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.threshold.String(), func(t *testing.T) {
			withLevel(t, tt.threshold)

			buf := captureLog(t)
			Infof("INFO_LINE")
			if got := strings.Contains(buf.String(), "INFO_LINE"); got != tt.wantInfo {
				t.Errorf("info emitted = %v, want %v", got, tt.wantInfo)
			}

			buf.Reset()
			Warnf("WARN_LINE")
			if got := strings.Contains(buf.String(), "WARN_LINE"); got != tt.wantWarn {
				t.Errorf("warn emitted = %v, want %v", got, tt.wantWarn)
			}

			buf.Reset()
			Errorf("ERROR_LINE")
			if got := strings.Contains(buf.String(), "ERROR_LINE"); got != tt.wantError {
				t.Errorf("error emitted = %v, want %v", got, tt.wantError)
			}
		})
	}
}

// The default threshold with no explicit configuration must be info, so a
// deployment that omits logLevel is not silent and not flooded.
func TestDefaultLevelIsInfo(t *testing.T) {
	if got := GetLevel(); got != LevelInfo {
		t.Errorf("default level = %v, want info", got)
	}
}
