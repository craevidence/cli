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
