// Package behavior turns what the visitor's browser reports about how it was used into
// aggregate features for scoring: the altcha widget's human interaction signature (HIS,
// collected before the challenge is issued) and what the challenge page reports about the
// code step. It has no HTTP and no global state, like pkg/codechallenge.
//
// Everything here comes from the client and can be forged; a bot can replay a recorded
// human trace. The features are a signal for choosing how hard a challenge to show, never
// proof. Keyboard and screen-reader users have no pointer trace at all, so a missing trace
// must not by itself block anyone.
package behavior

import (
	"encoding/json"
	"errors"
	"math"
)

// MaxSamples bounds each HIS series. The widget keeps the last 60 samples of each; more
// means the client is not the stock widget.
const MaxSamples = 200

// HIS is the widget's human interaction signature (altcha 3.5.0 src/his.ts, Collector.export).
// Times are milliseconds from the page's time origin (performance.now()), except Time.
type HIS struct {
	// [elapsed ms since the first focus, tabIndex, tag code, 1 if the keyboard moved focus]
	Focus [][4]float64 `json:"focus"`
	// mouse or pen positions, at most one per 50 ms: [x, y, t]
	Pointer [][3]float64 `json:"pointer"`
	// [scrollY, t]
	Scroll [][2]float64 `json:"scroll"`
	// first touch point of each touchmove: [x, y, t, force, radiusX, radiusY]
	Touch          [][6]float64 `json:"touch"`
	MaxTouchPoints int          `json:"maxTouchPoints"`
	Time           int64        `json:"time"` // client clock, unix ms
}

// ParseHIS reads the body the widget posts to the HIS URL: {"his": {...}}.
func ParseHIS(body []byte) (HIS, error) {
	var req struct {
		HIS *HIS `json:"his"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return HIS{}, err
	}
	if req.HIS == nil {
		return HIS{}, errors.New("behavior: no his field")
	}
	h := *req.HIS
	if len(h.Focus) > MaxSamples || len(h.Pointer) > MaxSamples || len(h.Scroll) > MaxSamples || len(h.Touch) > MaxSamples {
		return HIS{}, errors.New("behavior: more samples than the widget sends")
	}
	// screen coordinates and page times; anything far larger would overflow the features
	ok := true
	check := func(vs ...float64) {
		for _, v := range vs {
			ok = ok && math.Abs(v) <= maxValue
		}
	}
	for _, s := range h.Focus {
		check(s[:]...)
	}
	for _, s := range h.Pointer {
		check(s[:]...)
	}
	for _, s := range h.Scroll {
		check(s[:]...)
	}
	for _, s := range h.Touch {
		check(s[:]...)
	}
	if !ok {
		return HIS{}, errors.New("behavior: sample out of range")
	}
	return h, nil
}

// maxValue bounds every HIS number: a day in ms, far beyond any screen in px.
const maxValue = 1e8

// HISFeatures summarise a HIS. Zero values mean "no data" for that series.
type HISFeatures struct {
	PointerSamples int `json:"pointer_n"`
	TouchSamples   int `json:"touch_n"`
	ScrollSamples  int `json:"scroll_n"`
	FocusSamples   int `json:"focus_n"`
	MaxTouchPoints int `json:"max_touch_points"`
	// focus moves made with the keyboard (Tab), a sign of keyboard or screen-reader use
	KeyboardFocus int `json:"keyboard_focus_n"`

	// the pointer (or touch, if there is no pointer) trace
	FirstMoveMs   float64 `json:"first_move_ms"`  // page time of the first sample
	SpanMs        float64 `json:"span_ms"`        // first to last sample
	PathPx        float64 `json:"path_px"`        // length of the path
	Straightness  float64 `json:"straightness"`   // start-to-end distance / path; 1 is a ruler line
	SpeedMean     float64 `json:"speed_mean"`     // px per ms
	SpeedCV       float64 `json:"speed_cv"`       // speed std / mean; scripted moves are even
	IntervalMean  float64 `json:"interval_mean"`  // ms between samples
	IntervalCV    float64 `json:"interval_cv"`    // std / mean of those intervals
	Pauses        int     `json:"pauses_n"`       // gaps over 250 ms
	TurnMeanRad   float64 `json:"turn_mean_rad"`  // mean change of direction between segments
	SharpTurns    int     `json:"sharp_turns_n"`  // direction changes over 90°
	StillSegments int     `json:"still_n"`        // samples that did not move
	TouchForceSD  float64 `json:"touch_force_sd"` // synthetic touches often have constant force
	TouchRadiusSD float64 `json:"touch_radius_sd"`
}

// Features computes HISFeatures.
func Features(h HIS) HISFeatures {
	f := HISFeatures{
		PointerSamples: len(h.Pointer),
		TouchSamples:   len(h.Touch),
		ScrollSamples:  len(h.Scroll),
		FocusSamples:   len(h.Focus),
		MaxTouchPoints: h.MaxTouchPoints,
	}
	for _, s := range h.Focus {
		if s[3] == 1 {
			f.KeyboardFocus++
		}
	}
	trace := make([][3]float64, 0, max(len(h.Pointer), len(h.Touch)))
	if len(h.Pointer) > 0 {
		trace = append(trace, h.Pointer...)
	} else {
		for _, s := range h.Touch {
			trace = append(trace, [3]float64{s[0], s[1], s[2]})
		}
	}
	traceFeatures(&f, trace)
	if len(h.Touch) > 1 {
		force := make([]float64, len(h.Touch))
		radius := make([]float64, len(h.Touch))
		for i, s := range h.Touch {
			force[i], radius[i] = s[3], (s[4]+s[5])/2
		}
		_, f.TouchForceSD = meanSD(force)
		_, f.TouchRadiusSD = meanSD(radius)
	}
	return f
}

func traceFeatures(f *HISFeatures, trace [][3]float64) {
	if len(trace) == 0 {
		return
	}
	f.FirstMoveMs = trace[0][2]
	f.SpanMs = trace[len(trace)-1][2] - trace[0][2]
	if len(trace) < 2 {
		return
	}
	var speeds, intervals, turns []float64
	prevAngle, havePrev := 0.0, false
	for i := 1; i < len(trace); i++ {
		dx, dy, dt := trace[i][0]-trace[i-1][0], trace[i][1]-trace[i-1][1], trace[i][2]-trace[i-1][2]
		d := math.Hypot(dx, dy)
		f.PathPx += d
		if dt > 0 {
			intervals = append(intervals, dt)
			speeds = append(speeds, d/dt)
			if dt > 250 {
				f.Pauses++
			}
		}
		if d == 0 {
			f.StillSegments++
			continue
		}
		angle := math.Atan2(dy, dx)
		if havePrev {
			turn := math.Abs(angle - prevAngle)
			if turn > math.Pi {
				turn = 2*math.Pi - turn
			}
			turns = append(turns, turn)
			if turn > math.Pi/2 {
				f.SharpTurns++
			}
		}
		prevAngle, havePrev = angle, true
	}
	if f.PathPx > 0 {
		first, last := trace[0], trace[len(trace)-1]
		f.Straightness = math.Hypot(last[0]-first[0], last[1]-first[1]) / f.PathPx
	}
	f.SpeedMean, f.SpeedCV = meanCV(speeds)
	f.IntervalMean, f.IntervalCV = meanCV(intervals)
	f.TurnMeanRad, _ = meanSD(turns)
}

// CodeStep is what the challenge page reports about the code form. Durations in ms.
type CodeStep struct {
	ShownMs     float64   `json:"shown_ms"`     // code form shown to submit
	Keys        int       `json:"keys"`         // keydowns in the code input
	KeyGapsMs   []float64 `json:"key_gaps_ms"`  // between those keydowns
	Pasted      bool      `json:"pasted"`       // a paste into the code input
	AudioPlayed bool      `json:"audio_played"` // the spoken code was played
	Reloads     int       `json:"reloads"`      // new images asked for before this submit
}

// CodeStepFeatures summarise a CodeStep.
type CodeStepFeatures struct {
	ShownMs     float64 `json:"shown_ms"`
	Keys        int     `json:"keys"`
	KeyGapMean  float64 `json:"key_gap_mean"`
	KeyGapCV    float64 `json:"key_gap_cv"`
	Pasted      bool    `json:"pasted"`
	AudioPlayed bool    `json:"audio_played"`
	Reloads     int     `json:"reloads"`
}

// maxKeyGaps bounds CodeStep.KeyGapsMs: a code is a few digits, corrections included.
const maxKeyGaps = 100

// Summarise checks a CodeStep and computes its features.
func (c CodeStep) Summarise() (CodeStepFeatures, error) {
	bad := len(c.KeyGapsMs) > maxKeyGaps || c.Keys < 0 || c.Reloads < 0 || c.ShownMs < 0 || c.ShownMs > maxValue
	for _, g := range c.KeyGapsMs {
		bad = bad || g < 0 || g > maxValue
	}
	if bad {
		return CodeStepFeatures{}, errors.New("behavior: implausible code step")
	}
	f := CodeStepFeatures{
		ShownMs:     c.ShownMs,
		Keys:        c.Keys,
		Pasted:      c.Pasted,
		AudioPlayed: c.AudioPlayed,
		Reloads:     c.Reloads,
	}
	f.KeyGapMean, f.KeyGapCV = meanCV(c.KeyGapsMs)
	return f, nil
}

func meanSD(xs []float64) (mean, sd float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	for _, x := range xs {
		sd += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(sd / float64(len(xs)))
}

// meanCV returns the mean and the coefficient of variation (sd / mean, 0 if mean is 0).
func meanCV(xs []float64) (mean, cv float64) {
	mean, sd := meanSD(xs)
	if mean == 0 {
		return mean, 0
	}
	return mean, sd / mean
}
