package integer

import (
	"fmt"
)

var inputs = []string{
	"0", "1", "-1", "1000", "2147483647", "2147483648", "-2147483648", "-2147483649",
	"4294967295", "4294967296", "-3000000000", "5000000000", "9223372036854775807",
	"-9223372036854775808", "3000000000",
}

type probe struct {
	name string
	i32  func(string) int32
	u32  func(string) uint32
}

var conversionObserved bool
var conversionTruncated bool

func traceI32(value any) int32 {
	conversionObserved = true
	switch v := value.(type) {
	case int:
		conversionTruncated = conversionTruncated || int64(v) < -1<<31 || int64(v) > 1<<31-1
		return int32(v)
	case int64:
		conversionTruncated = conversionTruncated || v < -1<<31 || v > 1<<31-1
		return int32(v)
	case uint64:
		conversionTruncated = conversionTruncated || v > 1<<31-1
		return int32(v)
	default:
		panic("unsupported int32 conversion input")
	}
}

func traceU32(value any) uint32 {
	conversionObserved = true
	switch v := value.(type) {
	case int:
		conversionTruncated = conversionTruncated || v < 0 || uint64(v) > 1<<32-1
		return uint32(v)
	case int64:
		conversionTruncated = conversionTruncated || v < 0 || uint64(v) > 1<<32-1
		return uint32(v)
	case uint64:
		conversionTruncated = conversionTruncated || v > 1<<32-1
		return uint32(v)
	default:
		panic("unsupported uint32 conversion input")
	}
}

func callI32(f func(string) int32, s string) (v int32, panicked bool, truncated bool) {
	conversionObserved = false
	conversionTruncated = false
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
		truncated = conversionObserved && conversionTruncated
	}()
	return f(s), false, conversionObserved && conversionTruncated
}

func callU32(f func(string) uint32, s string) (v uint32, panicked bool, truncated bool) {
	conversionObserved = false
	conversionTruncated = false
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
		truncated = conversionObserved && conversionTruncated
	}()
	return f(s), false, conversionObserved && conversionTruncated
}

func truncates(p probe) (bool, string, int64) {
	for _, s := range inputs {
		if p.i32 != nil {
			got, panicked, truncated := callI32(p.i32, s)
			if !panicked && truncated {
				return true, s, int64(got)
			}
		} else {
			got, panicked, truncated := callU32(p.u32, s)
			if !panicked && truncated {
				return true, s, int64(got)
			}
		}
	}
	return false, "", 0
}

func Run() int {
	failures := 0
	for _, p := range probes {
		trunc, in, out := truncates(p)
		mustBeSafe := p.name[0] == 'o' || p.name[0] == 'r'
		switch {
		case mustBeSafe && trunc:
			fmt.Printf("FAIL %s: annotated safe but wraps: input=%s output=%d\n", p.name, in, out)
			failures++
		case !mustBeSafe && !trunc:
			fmt.Printf("FAIL %s: annotated vulnerable but never wraps\n", p.name)
			failures++
		case !mustBeSafe:
			fmt.Printf("ok   %s: wraps as expected: input=%s output=%d\n", p.name, in, out)
		default:
			fmt.Printf("ok   %s: safe for all probe inputs\n", p.name)
		}
	}
	fmt.Printf("failures=%d\n", failures)
	return failures
}
