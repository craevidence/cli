package integer

import (
	"math"
	"strconv"
)

// Branch 1: ParseInt 64 -> int32 without bounds check
func badParseIntToInt32(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseInt(s, 10, 64)
	return int32(x)
}

// Branch 2: ParseInt 64 -> uint32 without bounds check
func badParseIntToUint32(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseInt(s, 10, 64)
	return uint32(x)
}

// Branch 3: ParseUint 64 -> int32 without bounds check
func badParseUintToInt32(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseUint(s, 10, 64)
	return int32(x)
}

// Branch 4: ParseUint 64 -> uint32 without bounds check
func badParseUintToUint32(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseUint(s, 10, 64)
	return uint32(x)
}

// Branch 5: Atoi -> int32 without bounds check
func badAtoiToInt32(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	x, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return int32(x)
}

// Branch 6: Atoi -> uint32 without bounds check
func badAtoiToUint32(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	x, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return uint32(x)
}

// Safe: parse with bitSize 32 so strconv enforces the range
func okParseIntBitSize32(s string) int32 {
	x, _ := strconv.ParseInt(s, 10, 32)
	// ok: cra-go-parseint-downcast
	return int32(x)
}

// Safe: explicit MaxInt32 bounds check before cast
func okParseIntBoundsChecked(s string) int32 {
	x, _ := strconv.ParseInt(s, 10, 64)
	if x > math.MaxInt32 || x < math.MinInt32 {
		return 0
	}
	// ok: cra-go-parseint-downcast
	return int32(x)
}

// Safe: explicit MaxUint32 bounds check before cast
func okParseUintBoundsChecked(s string) uint32 {
	x, _ := strconv.ParseUint(s, 10, 64)
	if x > math.MaxUint32 {
		return 0
	}
	// ok: cra-go-parseint-downcast
	return uint32(x)
}
