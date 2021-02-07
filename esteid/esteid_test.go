package esteid

import (
	"testing"

	"github.com/ivokub/gopace"
)

var canReal []byte = []byte("050746")

func TestNewPlainCard(t *testing.T) {
	card, cancel, err := gopace.Connect()
	if err != nil {
		t.Fatalf("Error connecting: %v", err)
	}
	defer cancel()
	if err = ReadPersonalDFEntries(card); err != nil {
		t.Errorf("Error reading DF entries: %v", err)
	}
}

func TestSecureCard(t *testing.T) {
	pcard, cancel, err := gopace.Connect()
	if err != nil {
		t.Fatalf("Establish context: %v+", err)
		return
	}
	defer cancel()
	scard, err := gopace.PACE(pcard, canReal)
	if err != nil {
		t.Fatalf("PACE: %v+", err)
	}
	if err = ReadPersonalDFEntries(scard); err != nil {
		t.Errorf("Error reading DF entries: %v", err)
	}
}
