package gopace

import (
	"testing"
)

func TestPACE(t *testing.T) {
	pcard, cancel, err := Connect()
	if err != nil {
		t.Fatalf("Establish context: %v+", err)
		return
	}
	defer cancel()
	scard, err := PACE(pcard, canReal)
	if err != nil {
		t.Fatalf("PACE: %v+", err)
	}
	_ = scard
}
