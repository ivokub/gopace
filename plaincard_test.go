package main

import "testing"

func TestNewPlainCard(t *testing.T) {
	card, cancel, err := Connect()
	if err != nil {
		t.Fatalf("Error connecting: %v", err)
	}
	defer cancel()
	if err = ReadPersonalDFEntries(card); err != nil {
		t.Errorf("Error reading DF entries: %v", err)
	}
}
