package gopace

import (
	"fmt"
)

var (
	apduSelectApplication = []byte{0x00, 0xa4, 0x04, 0x00}
	apduSelectFile        = []byte{0x00, 0xA4, 0x01, 0x0C}
	apduReadBinary        = []byte{0x00, 0xB0, 0x00, 0x00}
	swSuccess             = []byte{0x90, 0x00}
)

// Carder abstracts communication between host and card over insecure and secure channel
type Carder interface {
	Transmit(header []byte, data []byte, le []byte) (resp []byte, err error)
	TransmitAPDU(apdu []byte) (resp []byte, err error)
}

// SelectFile selects a file given the file identifier and a Carder.
func SelectFile(card Carder, file []byte) (err error) {
	fmt.Printf("== Selecting file: %X\n", file)
	_, err = card.Transmit(apduSelectFile, file, nil)
	if err != nil {
		return err
	}
	return nil
}

// ReadBinary reads the content of an already chosen file.
func ReadBinary(card Carder) (content []byte, err error) {
	content, err = card.Transmit(apduReadBinary, nil, []byte{0x00})
	if err != nil {
		return nil, err
	}
	return content, nil
}
