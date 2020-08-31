package main

import (
	"bytes"
	"fmt"

	"github.com/ebfe/scard"
)

type PlainCard struct {
	card *scard.Card
}

var EsteIDApplication = []byte{0xa0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00,
	0x00, 0x01}

func Connect() (pcard *PlainCard, cancel func(), err error) {
	context, err := scard.EstablishContext()
	if err != nil {
		fmt.Println("Error EstablishContext:", err)
		return
	}

	// List available readers
	readers, err := context.ListReaders()
	if err != nil {
		fmt.Println("Error ListReaders:", err)
		return
	}

	fmt.Printf("Detected readers: %v\n", readers)
	// Use the first reader
	reader := readers[0]
	fmt.Println("== Using reader:", reader)

	// Connect to the card
	card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		fmt.Println("Error Connect:", err)
		return
	}
	pcard = &PlainCard{card}
	// Send select APDU
	_, err = pcard.Transmit(apduSelectApplication, EsteIDApplication, []byte{0x00})
	if err != nil {
		fmt.Println(err)
		return
	}
	cancel = func() {
		card.Disconnect(scard.LeaveCard)
		context.Release()
	}
	return &PlainCard{card}, cancel, nil
}

func (pcard *PlainCard) Transmit(header []byte, data []byte, le []byte) (resp []byte, err error) {
	apdu := GetAPDU(header, data, le)
	resp, err = pcard.TransmitAPDU(apdu)
	if err != nil {
		return nil, fmt.Errorf("TransmitAPDU: %w", err)
	}
	return resp, err
}

func (pcard *PlainCard) TransmitAPDU(apdu []byte) (resp []byte, err error) {
	fmt.Printf("C-APDU > [%X]\n", apdu)
	rcv, err := pcard.card.Transmit(apdu)
	if err != nil {
		return nil, fmt.Errorf("Error transmitting APDU: %w", err)
	}
	sw := rcv[len(rcv)-2:]
	if !bytes.Equal(sw, swSuccess) {
		return nil, fmt.Errorf("Command failed: %x", sw)
	}
	resp = rcv[0 : len(rcv)-2]
	fmt.Printf("R-APDU < SW: [%X] Data: [%X]\n", sw, resp)
	return resp, err
}

func GetAPDU(header, data []byte, le []byte) (apdu []byte) {
	apdu = append(apdu, header...)
	if len(data) > 0 {
		apdu = append(header, byte(len(data)))
		apdu = append(apdu, data...)
	}
	apdu = append(apdu, le...)
	return apdu
}
