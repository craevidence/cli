package concurrency

import "sync"

// Branch 1: Lock() + defer RUnlock() -- mismatched
func badLockRUnlock(mu *sync.RWMutex) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.Lock()
	defer mu.RUnlock()
}

// Branch 2: RLock() + defer Unlock() -- mismatched
func badRLockUnlock(mu *sync.RWMutex) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.RLock()
	defer mu.Unlock()
}

// Branch 3: Lock() + defer Lock() -- double lock, deadlock
func badLockLock(mu *sync.Mutex) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.Lock()
	defer mu.Lock()
}

// Branch 4: RLock() + defer RLock() -- second RLock in defer won't deadlock
// but is still a misuse detected by this rule
func badRLockRLock(mu *sync.RWMutex) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.RLock()
	defer mu.RLock()
}

func badLockRUnlockAfterStatement(mu *sync.RWMutex) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.Lock()
	value := 1
	defer mu.RUnlock()
	_ = value
}

// Branch 5: Lock() + deferred closure calling RUnlock() -- mismatched
func badLockDeferredClosureRUnlock(mu *sync.RWMutex) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.Lock()
	defer func() { mu.RUnlock() }()
}

// Branch 6: RLock() + deferred closure calling Unlock() -- mismatched
func badRLockDeferredClosureUnlock(mu *sync.RWMutex) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.RLock()
	defer func() { mu.Unlock() }()
}

// A conditional release does not make the deferred read unlock pair with the
// write lock on every path.
func badLockRUnlockAfterConditionalRelease(mu *sync.RWMutex, release bool) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.Lock()
	if release {
		mu.Unlock()
	}
	defer mu.RUnlock()
}

// Mirror of the conditional-release mismatch above.
func badRLockUnlockAfterConditionalRelease(mu *sync.RWMutex, release bool) {
	// ruleid: cra-go-wrong-lock-unlock
	mu.RLock()
	if release {
		mu.RUnlock()
	}
	defer mu.Unlock()
}

// Safe: Lock() + deferred closure calling Unlock() -- correct pair
func okLockDeferredClosureUnlock(mu *sync.RWMutex) {
	// ok: cra-go-wrong-lock-unlock
	mu.Lock()
	defer func() { mu.Unlock() }()
}

// Safe: RLock() + deferred closure calling RUnlock() -- correct pair
func okRLockDeferredClosureRUnlock(mu *sync.RWMutex) {
	// ok: cra-go-wrong-lock-unlock
	mu.RLock()
	defer func() { mu.RUnlock() }()
}

// Safe: Lock() + defer Unlock() -- correct pair
func okLockUnlock(mu *sync.Mutex) {
	// ok: cra-go-wrong-lock-unlock
	mu.Lock()
	defer mu.Unlock()
}

// Safe: RLock() + defer RUnlock() -- correct pair
func okRLockRUnlock(mu *sync.RWMutex) {
	// ok: cra-go-wrong-lock-unlock
	mu.RLock()
	defer mu.RUnlock()
}

// Safe: a write section closed explicitly, then a read section with a matching
// deferred unlock. Read then upgrade to write and its mirror are ordinary Go.
func okWriteSectionThenReadSection(mu *sync.RWMutex) {
	mu.Lock()
	mu.Unlock()

	// ok: cra-go-wrong-lock-unlock
	mu.RLock()
	defer mu.RUnlock()
}

// Safe: a read section closed explicitly, then a write section.
func okReadSectionThenWriteSection(mu *sync.RWMutex) {
	mu.RLock()
	mu.RUnlock()

	// ok: cra-go-wrong-lock-unlock
	mu.Lock()
	defer mu.Unlock()
}

// Safe: the deferred read unlock belongs to a read section opened inside a
// nested closure, not to the write section that already closed.
func okClosureReadSectionAfterWriteSection(mu *sync.RWMutex) {
	mu.Lock()
	mu.Unlock()

	func() {
		// ok: cra-go-wrong-lock-unlock
		mu.RLock()
		defer mu.RUnlock()
	}()
}

// A file lock whose Unlock releases whichever mode is held, so RLock pairs with
// Unlock and there is no RUnlock method at all.
type fileLock struct {
	mu sync.RWMutex
}

func (l *fileLock) Lock()   { l.mu.Lock() }
func (l *fileLock) RLock()  { l.mu.RLock() }
func (l *fileLock) Unlock() { l.mu.Unlock() }

// Safe: the receiver is not a sync mutex, so the sync pairing rule does not
// apply to it.
func okNonSyncLockerReadThenUnlock(l *fileLock) {
	// ok: cra-go-wrong-lock-unlock
	l.RLock()
	defer l.Unlock()
}
