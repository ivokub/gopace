package esteid

import (
	"fmt"

	"github.com/ivokub/gopace"
)

var (
	personalDF        = []byte{0x50, 0x00}
	esteIDApplication = []byte{0xa0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00,
		0x00, 0x01}
)

// ReadPersonalDFEntries reads the personal data file entries from a card.
func ReadPersonalDFEntries(card gopace.Carder) (err error) {
	err = gopace.SelectFile(card, personalDF)
	if err != nil {
		return err
	}
	for i := byte(1); i < 16; i++ {
		err = gopace.SelectFile(card, []byte{0x50, i})
		if err != nil {
			return err
		}
		content, err := gopace.ReadBinary(card)
		if err != nil {
			return err
		}
		fmt.Printf("==> Entry %d: %s\n", i, content)
	}
	return nil
}
