//
// Copyright 2026 The Sigstore Authors.
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

package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestConfigureLoggerProdEncoder(t *testing.T) {
	origLogger := Logger
	t.Cleanup(func() {
		Logger = origLogger
	})

	ConfigureLogger("prod", "")

	var buf bytes.Buffer
	// Rebuild a core using the same encoder config as ConfigureLogger("prod")
	// to capture output deterministically.
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.LevelKey = "severity"
	cfg.EncoderConfig.MessageKey = "message"
	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.EncodeLevel = encodeLevel()
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	cfg.EncoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
	cfg.EncoderConfig.EncodeCaller = zapcore.FullCallerEncoder

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(cfg.EncoderConfig),
		zapcore.AddSync(&buf),
		zapcore.DebugLevel,
	)
	logger := zap.New(core, zap.AddCaller()).Sugar()
	logger.Warnw("test warning", "dur", 1500*time.Millisecond)

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to unmarshal log output %q: %v", buf.String(), err)
	}

	if got := entry["severity"]; got != "WARNING" {
		t.Errorf("expected severity %q, got %v", "WARNING", got)
	}
	if got := entry["message"]; got != "test warning" {
		t.Errorf("expected message %q, got %v", "test warning", got)
	}
	timeStr, ok := entry["time"].(string)
	if !ok {
		t.Fatalf("expected string time field, got %T (%v)", entry["time"], entry["time"])
	}
	if _, err := time.Parse(time.RFC3339Nano, timeStr); err != nil {
		t.Errorf("expected RFC3339Nano time, got %q: %v", timeStr, err)
	}
	caller, ok := entry["caller"].(string)
	if !ok || !strings.Contains(caller, "pkg/log/log_test.go:") {
		t.Errorf("expected full caller path containing pkg/log/log_test.go:, got %v", entry["caller"])
	}
	if got := entry["dur"]; got != float64(1.5) {
		t.Errorf("expected seconds duration 1.5, got %v", got)
	}
}
