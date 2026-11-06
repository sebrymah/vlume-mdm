package platformkeys

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *memLog) Info(m string, _ ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, "info: "+m)
	l.mu.Unlock()
}
func (l *memLog) Error(m string, _ ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, "error: "+m)
	l.mu.Unlock()
}
func (l *memLog) has(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, x := range l.lines {
		if strings.Contains(x, s) {
			return true
		}
	}
	return false
}

func TestTheKeysAreReReadWhileRunningAndABadSetIsNotApplied(t *testing.T) {
	dir := keyDir(t, 0o400)
	src := Files{Dir: dir}
	running, err := Load(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reload := make(chan struct{}, 1)
	var mu sync.Mutex
	var applied []Keys
	log := &memLog{}
	go Watch(ctx, src, time.Hour, reload, running, func(k Keys) error {
		mu.Lock()
		defer mu.Unlock()
		applied = append(applied, k)
		return nil
	}, log)

	count := func() int { mu.Lock(); defer mu.Unlock(); return len(applied) }
	settle := func(want int) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if count() == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("applied %d times, want %d", count(), want)
	}

	// Unchanged: a reload applies nothing.
	reload <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	if count() != 0 {
		t.Fatal("unchanged keys were applied")
	}
	// The sealing master turns over: applied, with the new fingerprint.
	newSealing := "a-new-sealing-master-32-bytes-!!"
	if err := os.WriteFile(filepath.Join(dir, SealingName), []byte(newSealing+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	reload <- struct{}{}
	settle(1)
	if string(applied[0].Sealing) != newSealing || string(applied[0].Claim) != claim {
		t.Fatalf("applied %q", applied[0].Describe())
	}
	if !log.has("rotated while running") {
		t.Fatal("the rotation was not logged")
	}
	// A bad set (one key doing two jobs): refused, the running keys stay.
	if err := os.WriteFile(filepath.Join(dir, SessionName), []byte(claim+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	reload <- struct{}{}
	time.Sleep(80 * time.Millisecond)
	if count() != 1 || !log.has("could not be re-read") {
		t.Fatalf("a bad set was applied, or not logged: %d %v", count(), log.lines)
	}
	// Put right, with a new session key: applied.
	if err := os.WriteFile(filepath.Join(dir, SessionName), []byte("a-new-session-signing-key-32-bytes!!\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	reload <- struct{}{}
	settle(2)
	if string(applied[1].Session) != "a-new-session-signing-key-32-bytes!!" || string(applied[1].Sealing) != newSealing {
		t.Fatalf("applied %q", applied[1].Describe())
	}
}
