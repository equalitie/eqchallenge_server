package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// recorder appends one JSON line per issued challenge and per verify to a file, for
// training a scoring model later. Lines of one challenge share its id. It records features
// only: no IP, no User-Agent, and raw interaction traces only when asked for (lab sessions).
// A nil recorder records nothing.
type recorder struct {
	mu    sync.Mutex
	f     *os.File
	label string // what kind of client this run serves, e.g. "human" or "bot-headless"
	raw   bool   // also record the widget's raw HIS
}

func openRecorder(path, label string, raw bool) (*recorder, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &recorder{f: f, label: label, raw: raw}, nil
}

func (r *recorder) record(event, id string, fields map[string]any) {
	if r == nil {
		return
	}
	line := map[string]any{"t": time.Now().UTC().Format(time.RFC3339Nano), "event": event, "id": id, "label": r.label}
	for k, v := range fields {
		line[k] = v
	}
	b, err := json.Marshal(line)
	if err != nil {
		log.Printf("record %s: %v", event, err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.f.Write(append(b, '\n')); err != nil {
		log.Printf("record %s: %v", event, err)
	}
}
