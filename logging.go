package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// slog-lite: one JSON line per event on stderr. Structured because the
// dashboard, 9router, or grepping a VPS journal all want fields, not prose.
// Deliberately not log/slog: stdlib slog lands in containers as one line per
// handler anyway, and we keep zero deps.
//
// ponytail: stderr-only, unbuffered. A --log-file flag is the upgrade path; a
// journald/Windows-service wrapper handles persistence today.

type event struct {
	Time  string          `json:"ts"`
	Level string          `json:"level"`
	Event string          `json:"event"`
	Err   string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

var logMu sync.Mutex

func logJSON(level, event_ string, kv ...any) {
	rec := event{
		Time:  time.Now().UTC().Format(time.RFC3339Nano),
		Level: level,
		Event: event_,
	}
	if len(kv) > 0 {
		d := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			key, ok := kv[i].(string)
			if !ok {
				key = fmt.Sprintf("arg%d", i/2)
			}
			d[key] = kv[i+1]
		}
		if raw, err := json.Marshal(d); err == nil {
			rec.Data = raw
		} else {
			rec.Err = err.Error()
		}
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	os.Stderr.Write(append(line, '\n'))
}

func logInfo(name string, kv ...any) { logJSON("info", name, kv...) }
func logWarn(name string, kv ...any) { logJSON("warn", name, kv...) }
func logErr(name string, kv ...any)  { logJSON("error", name, kv...) }
