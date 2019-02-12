package validator

import (
	"fmt"
	"testing"
)

// func TestParseTagOnlyValidator(t *testing.T) {
// 	// ParseTag("required")
// }
// func TestParseTagWithParamsValidator(t *testing.T) {
// 	// ParseTag(`required("test")`)
// }
// func TestParseTagWithErrorValidator(t *testing.T) {
// 	// PaseTag(`required("test")`)
// }

var (
	k = map[string]func(v1, v2 int) bool{
		"int.<": func(v1, v2 int) bool {
			return v1 < v2
		},
	}
)

func c1(v1, v2 int, mode string) bool {
	switch mode {
	case "<":
		return v1 < v2
	}
	return false
}

func BenchmarkX(b *testing.B) {
	b.ReportAllocs()
	var (
		t bool
	)
	for n := 0; n < b.N; n++ {
		for i := 0; i < 1000000000; i++ {
			t = k["int.<"](i, i+1)
		}
	}

	fmt.Println(t)
}
func BenchmarkY(b *testing.B) {
	b.ReportAllocs()
	var (
		t bool
	)
	for n := 0; n < b.N; n++ {
		for i := 0; i < 1000000000; i++ {
			t = c1(i, i+1, "<")
		}
	}
	fmt.Println(t)
}

// (?P<validator>(\w+)(\((\"\w+\"|\w+)(,(\"\w+\"|\w+))*\))?)
