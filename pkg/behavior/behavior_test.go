package behavior

import (
	"encoding/json"
	"math"
	"testing"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// A scripted move: a straight line at constant speed, one sample every 50 ms.
func TestScriptedLine(t *testing.T) {
	var h HIS
	for i := range 10 {
		h.Pointer = append(h.Pointer, [3]float64{float64(10 * i), float64(5 * i), float64(1000 + 50*i)})
	}
	f := Features(h)
	if f.PointerSamples != 10 || f.FirstMoveMs != 1000 || f.SpanMs != 450 {
		t.Fatalf("counts: %+v", f)
	}
	if !near(f.Straightness, 1) || !near(f.SpeedCV, 0) || !near(f.IntervalCV, 0) || f.TurnMeanRad > 1e-9 || f.SharpTurns != 0 {
		t.Fatalf("a ruler line at constant speed: %+v", f)
	}
	if !near(f.PathPx, 9*math.Hypot(10, 5)) {
		t.Fatalf("path %v", f.PathPx)
	}
}

// A wobbly move with uneven timing, a pause and a turn back.
func TestWobblyMove(t *testing.T) {
	h := HIS{Pointer: [][3]float64{
		{0, 0, 0}, {12, 3, 55}, {20, 9, 130}, {21, 9, 190}, {21, 9, 260},
		{40, 2, 600}, {35, 4, 660},
	}}
	f := Features(h)
	if f.Straightness >= 0.9 || f.SpeedCV == 0 || f.IntervalCV == 0 {
		t.Fatalf("looks scripted: %+v", f)
	}
	if f.Pauses != 1 || f.StillSegments != 1 || f.SharpTurns < 1 {
		t.Fatalf("pause, still sample, turn back: %+v", f)
	}
}

func TestTouchOnly(t *testing.T) {
	h := HIS{MaxTouchPoints: 5, Touch: [][6]float64{
		{100, 400, 2000, 0.5, 20, 22}, {104, 380, 2050, 0.6, 21, 21}, {110, 350, 2100, 0.4, 19, 23},
	}}
	f := Features(h)
	if f.TouchSamples != 3 || f.PathPx == 0 || f.FirstMoveMs != 2000 || f.TouchForceSD == 0 {
		t.Fatalf("touch trace not used: %+v", f)
	}
	h.Touch[1][3], h.Touch[2][3] = 0.5, 0.5
	if f := Features(h); f.TouchForceSD != 0 {
		t.Fatalf("constant force: sd %v", f.TouchForceSD)
	}
}

// Keyboard and screen-reader use: no trace at all, focus moved with Tab.
func TestKeyboardOnly(t *testing.T) {
	h := HIS{Focus: [][4]float64{{0, 0, 5, 1}, {800, 0, 1, 1}, {1500, 0, 4, 0}}}
	f := Features(h)
	if f.KeyboardFocus != 2 || f.PointerSamples != 0 || f.PathPx != 0 || f.Straightness != 0 {
		t.Fatalf("%+v", f)
	}
}

func TestEmpty(t *testing.T) {
	if f := Features(HIS{}); f != (HISFeatures{}) {
		t.Fatalf("empty HIS: %+v", f)
	}
}

func TestParseHIS(t *testing.T) {
	body := `{"his":{"focus":[[0,0,1,0]],"maxTouchPoints":0,"pointer":[[1,2,3],[4,6,53]],"scroll":[],"time":1762800000000,"touch":[]}}`
	h, err := ParseHIS([]byte(body))
	if err != nil || len(h.Pointer) != 2 || h.Pointer[1][1] != 6 || h.Time != 1762800000000 {
		t.Fatalf("got %+v, %v", h, err)
	}
	tooMany := HIS{Pointer: make([][3]float64, MaxSamples+1)}
	b, _ := json.Marshal(map[string]HIS{"his": tooMany})
	for _, bad := range []string{"", "{}", `{"his":null}`, `{"his":{"pointer":"x"}}`, string(b),
		`{"his":{"pointer":[[1e300,0,0],[0,0,50]]}}`} {
		if _, err := ParseHIS([]byte(bad)); err == nil {
			t.Fatalf("accepted %.60q", bad)
		}
	}
}

func TestCodeStep(t *testing.T) {
	f, err := CodeStep{ShownMs: 5200, Keys: 6, KeyGapsMs: []float64{180, 220, 150, 400, 210}, AudioPlayed: true}.Summarise()
	if err != nil || f.Keys != 6 || !near(f.KeyGapMean, 232) || f.KeyGapCV == 0 || !f.AudioPlayed {
		t.Fatalf("got %+v, %v", f, err)
	}
	for _, bad := range []CodeStep{
		{Keys: -1}, {Reloads: -1}, {ShownMs: -5}, {ShownMs: 1e12},
		{KeyGapsMs: make([]float64, maxKeyGaps+1)}, {KeyGapsMs: []float64{-3}},
	} {
		if _, err := bad.Summarise(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
