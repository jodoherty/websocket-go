package ws

import (
	"testing"
	"time"
)

// TestKeepaliveDecision pins the keepalive timing boundary exactly. The
// decision is pure (lastActivity, now, idle → ping? deadline), so no clock
// or socket is involved: the cases that matter — "quiet enough to ping",
// "exactly at the boundary", "one nanosecond past it" — are testable
// deterministically.
func TestKeepaliveDecision(t *testing.T) {
	base := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	idle := 30 * time.Second

	cases := []struct {
		name         string
		lastActivity time.Time
		now          time.Time
		wantPing     bool
		wantDeadline time.Time
	}{
		{
			name:         "quiet within the window: no ping, deadline at window end",
			lastActivity: base,
			now:          base.Add(10 * time.Second),
			wantPing:     false,
			wantDeadline: base.Add(idle),
		},
		{
			name:         "exactly at the boundary: no ping (After, not !Before)",
			lastActivity: base,
			now:          base.Add(idle),
			wantPing:     false,
			wantDeadline: base.Add(idle),
		},
		{
			name:         "one nanosecond past the boundary: ping, fresh window",
			lastActivity: base,
			now:          base.Add(idle + time.Nanosecond),
			wantPing:     true,
			wantDeadline: base.Add(2*idle + time.Nanosecond),
		},
		{
			name:         "long idle: ping, window restarts from now",
			lastActivity: base,
			now:          base.Add(5 * time.Minute),
			wantPing:     true,
			wantDeadline: base.Add(5*time.Minute + idle),
		},
		{
			name:         "activity after now is impossible, but must not ping",
			lastActivity: base.Add(idle),
			now:          base,
			wantPing:     false,
			wantDeadline: base.Add(2 * idle),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ping, deadline := keepaliveDecision(tc.lastActivity, tc.now, idle)
			if ping != tc.wantPing {
				t.Errorf("ping = %v, want %v", ping, tc.wantPing)
			}
			if !deadline.Equal(tc.wantDeadline) {
				t.Errorf("deadline = %v, want %v", deadline, tc.wantDeadline)
			}
		})
	}
}
