package integer

import (
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
)

type returningOS struct{}

func (returningOS) Exit(int) {}

type returningLogger struct{}

func (returningLogger) Fatal(...any) {}

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

// Bad: the bounds check tests an unrelated variable, the cast is unguarded
func badDecoyBoundsCheck(s string, other int64) int32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseInt(s, 10, 64)
	if other > math.MaxInt32 {
		return 0
	}
	return int32(x)
}

// Bad: the bounds check tests a different parsed value
func badBoundsCheckOnOtherValue(a, b string) int32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseInt(a, 10, 64)
	y, _ := strconv.ParseInt(b, 10, 64)
	if y > math.MaxInt32 {
		return 0
	}
	return int32(x)
}

// Bad: parse and cast both sit inside a guard on an unrelated variable
func badNestedDecoyBoundsCheck(s string, other int64) int32 {
	if other > math.MaxInt32 {
		// ruleid: cra-go-parseint-downcast
		x, _ := strconv.ParseInt(s, 10, 64)
		return int32(x)
	}
	return 0
}

// Bad: a signed parse checked only against an upper bound. ParseInt("-3000000000")
// passes "x < 1000" and converts to 1294967296.
func badSignedUpperBoundOnly(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseInt(s, 10, 64)
	if x < 1000 {
		return uint32(x)
	}
	return 0
}

// Bad: the same gap with the constant on the left. ParseInt("-3000000000")
// passes "math.MaxInt32 < x" and converts to 1294967296.
func badReversedOperandsUpperOnly(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseInt(s, 10, 64)
	if math.MaxInt32 < x {
		return 0
	}
	return int32(x)
}

// Bad: a signed parse checked against a literal that is exactly the 32-bit
// maximum still lets every negative value through.
func badSignedLiteralAtMaxOnly(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseInt(s, 10, 64)
	if v < 2147483647 {
		return int32(v)
	}
	return 0
}

// Bad: the rejecting branch neither terminates nor encloses the cast, so the
// out-of-range value reaches the conversion anyway.
func badGuardWithoutTermination(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseInt(s, 10, 64)
	if v > math.MaxInt32 {
		fmt.Println("too large")
	}
	return int32(v)
}

// Bad: bitSize 0 selects int, which is 64 bits wide on a 64-bit platform
func badParseIntBitSizeZero(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseInt(s, 10, 0)
	return int32(v)
}

// Bad: the same for an unsigned parse
func badParseUintBitSizeZero(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseUint(s, 10, 0)
	return uint32(v)
}

// Bad: any bitSize above 32 leaves values the target type cannot hold
func badParseIntBitSize48(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseInt(s, 10, 48)
	return int32(v)
}

// Bad: the branch that rejects the value performs the cast itself, so the
// out-of-range value is truncated on the path meant to reject it.
func badCastInRejectingBranch(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseUint(s, 10, 64)
	if v > math.MaxUint32 {
		return uint32(v)
	}
	return 0
}

// Bad: the literal upper bound is larger than the 32-bit range
func badBoundsCheckLiteralTooLarge(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseInt(s, 10, 64)
	if v < 5000000000 {
		return int32(v)
	}
	return 0
}

// Bad: only a lower bound is checked
func badBoundsCheckLowerOnly(s string) int32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseInt(s, 10, 64)
	if v > 100 {
		return int32(v)
	}
	return 0
}

// Safe: both ends of the int32 range are checked and the cast sits inside the
// branch taken when the value is in range
func okBoundsCheckAroundCast(s string) int32 {
	x, _ := strconv.ParseInt(s, 10, 64)
	if x <= math.MaxInt32 && x >= math.MinInt32 {
		// ok: cra-go-parseint-downcast
		return int32(x)
	}
	return 0
}

// Safe: both ends of the int32 range as literals, cast inside the branch
func okSignedLiteralBothBounds(s string) int32 {
	v, _ := strconv.ParseInt(s, 10, 64)
	if v >= -2147483648 && v <= 2147483647 {
		// ok: cra-go-parseint-downcast
		return int32(v)
	}
	return 0
}

// Safe: both ends as literals in a rejecting guard that returns
func okSignedLiteralBothBoundsRejected(s string) int32 {
	v, _ := strconv.ParseInt(s, 10, 64)
	if v < -2147483648 || v > 2147483647 {
		return 0
	}
	// ok: cra-go-parseint-downcast
	return int32(v)
}

// Safe: a signed parse cast to uint32 with the zero floor stated
func okSignedToUint32BothBounds(s string) uint32 {
	v, _ := strconv.ParseInt(s, 10, 64)
	if v >= 0 && v <= 4294967295 {
		// ok: cra-go-parseint-downcast
		return uint32(v)
	}
	return 0
}

// Safe: unsigned parse, the literal upper bound fits well inside the 32-bit range
func okBoundsCheckSmallLiteral(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 64)
	if v < 1000 {
		// ok: cra-go-parseint-downcast
		return uint32(v)
	}
	return 0
}

// Safe: unsigned parse, literal upper bound below the uint32 maximum
func okParseUintLiteralBelowMax(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 64)
	if v < 4000000000 {
		// ok: cra-go-parseint-downcast
		return uint32(v)
	}
	return 0
}

// Safe: unsigned parse, inclusive bound at the uint32 maximum
func okParseUintLiteralAtMax(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 64)
	if v <= 4294967295 {
		// ok: cra-go-parseint-downcast
		return uint32(v)
	}
	return 0
}

// Safe: unsigned parse cast to int32, exclusive bound one past the int32 maximum
func okParseUintToInt32(s string) int32 {
	v, _ := strconv.ParseUint(s, 10, 64)
	if v < 2147483648 {
		// ok: cra-go-parseint-downcast
		return int32(v)
	}
	return 0
}

// Safe: both bounds stated, one as a math constant and one as a literal
func okMixedMathAndLiteralBounds(s string) int32 {
	v, _ := strconv.ParseInt(s, 10, 64)
	if v >= math.MinInt32 && v <= 2147483647 {
		// ok: cra-go-parseint-downcast
		return int32(v)
	}
	return 0
}

// Safe: a rejecting guard written with <= and >= instead of < and >
func okRejectNonStrictBounds(s string) int32 {
	v, _ := strconv.ParseInt(s, 10, 64)
	if v <= -2147483649 || v >= 2147483648 {
		return 0
	}
	// ok: cra-go-parseint-downcast
	return int32(v)
}

// Safe: the rejecting branch holds more than one statement before it returns
func okMultiStatementRejectGuard(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 64)
	if v > math.MaxUint32 {
		fmt.Println("value out of uint32 range")
		return 0
	}
	// ok: cra-go-parseint-downcast
	return uint32(v)
}

// Safe: the guard skips the out-of-range value with continue
func okRejectWithContinue(s string) uint32 {
	var out uint32
	for _, part := range strings.Split(s, ",") {
		v, _ := strconv.ParseUint(part, 10, 64)
		if v > math.MaxUint32 {
			continue
		}
		// ok: cra-go-parseint-downcast
		out = uint32(v)
	}
	return out
}

// Correct but reported: name matching cannot prove this is the real os package.
// This case takes a second parameter so the executable probe table skips it;
// calling it would end the test run.
func reportedRejectWithProcessExit(s string, code int) uint32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseUint(s, 10, 64)
	if v > math.MaxUint32 {
		os.Exit(code)
	}
	return uint32(v)
}

// Correct but reported for the same selector-resolution reason.
func reportedRejectWithFatalLog(s string, field string) uint32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseUint(s, 10, 64)
	if v > math.MaxUint32 {
		log.Fatalf("%s out of uint32 range", field)
	}
	return uint32(v)
}

// Bad: the local os value has a returning Exit method, so the cast still runs.
func badShadowedOSExit(s string) int32 {
	os := returningOS{}
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseInt(s, 10, 64)
	if v < math.MinInt32 || v > math.MaxInt32 {
		os.Exit(1)
	}
	return int32(v)
}

// Bad: the local log value has a returning Fatal method too.
func badShadowedLogFatal(s string) int32 {
	log := returningLogger{}
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseInt(s, 10, 64)
	if v < math.MinInt32 || v > math.MaxInt32 {
		log.Fatal("range")
	}
	return int32(v)
}

// Safe: parse with bitSize 32 so strconv enforces the range
func okParseIntBitSize32(s string) int32 {
	x, _ := strconv.ParseInt(s, 10, 32)
	// ok: cra-go-parseint-downcast
	return int32(x)
}

// Safe: an unsigned parse with bitSize 32, with the range error handled
func okParseUintBitSize32(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	// ok: cra-go-parseint-downcast
	return uint32(v)
}

// Safe: explicit MaxInt32 and MinInt32 bounds check before cast
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

// Reported although the check is correct: panic is a predeclared identifier and
// a local declaration rebinds it, so a call spelled panic(...) does not prove
// the branch ends execution. The rule does not accept it. Documented in the
// rule message.
func reportedPanicGuard(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	x, _ := strconv.ParseUint(s, 10, 64)
	if x > math.MaxUint32 {
		panic("value out of uint32 range")
	}
	return uint32(x)
}

// Reported although the check is correct: break leaves only the innermost for,
// switch, or select, so it does not show that the cast is skipped. The rule
// does not accept it. Documented in the rule message.
func reportedBreakRejectGuard(s string) uint32 {
	var out uint32
	for _, part := range strings.Split(s, ",") {
		// ruleid: cra-go-parseint-downcast
		v, _ := strconv.ParseUint(part, 10, 64)
		if v > math.MaxUint32 {
			break
		}
		out = uint32(v)
	}
	return out
}

// Reported although the check is correct: the bound is a named constant, which
// is not one of the shapes the rule recognizes. Documented in the rule message.
const maxUint32Bound uint64 = math.MaxUint32

func reportedNamedConstantBound(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseUint(s, 10, 64)
	if v > maxUint32Bound {
		return 0
	}
	return uint32(v)
}

// Reported although the check is correct: the bound is decided by a helper
// function, which the rule does not follow. Documented in the rule message.
func fitsUint32(v uint64) bool { return v <= math.MaxUint32 }

func reportedHelperPredicateBound(s string) uint32 {
	// ruleid: cra-go-parseint-downcast
	v, _ := strconv.ParseUint(s, 10, 64)
	if !fitsUint32(v) {
		return 0
	}
	return uint32(v)
}
