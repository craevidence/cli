package integer

import (
	"fmt"
	"math/big"
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

// wraps reports whether got is the low-32-bit reinterpretation of want, which
// is what a silent truncating conversion produces. A clamped or rejected value
// is not a wraparound.
func wrapsI32(want *big.Int, got int32) bool {
	m := new(big.Int).And(want, big.NewInt(0xFFFFFFFF))
	v := m.Int64()
	if v >= 1<<31 {
		v -= 1 << 32
	}
	return int64(got) == v && (!want.IsInt64() || want.Int64() != int64(got))
}

func wrapsU32(want *big.Int, got uint32) bool {
	m := new(big.Int).And(want, big.NewInt(0xFFFFFFFF))
	return uint64(got) == m.Uint64() && (!want.IsInt64() || want.Int64() != int64(got))
}

func callI32(f func(string) int32, s string) (v int32, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	return f(s), false
}

func callU32(f func(string) uint32, s string) (v uint32, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	return f(s), false
}

func truncates(p probe) (bool, string, int64) {
	for _, s := range inputs {
		want, ok := new(big.Int).SetString(s, 10)
		if !ok {
			continue
		}
		if p.i32 != nil {
			got, panicked := callI32(p.i32, s)
			if panicked || got == 0 {
				continue
			}
			if wrapsI32(want, got) {
				return true, s, int64(got)
			}
		} else {
			got, panicked := callU32(p.u32, s)
			if panicked || got == 0 {
				continue
			}
			if wrapsU32(want, got) {
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
