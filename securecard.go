package gopace

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/andreburgaud/crypt2go/ecb"
)

type SecureCard struct {
	kenc []byte
	kmac []byte
	ssc  uint64
	card Carder
}

func (sc *SecureCard) SSC() []byte {
	r := make([]byte, 16)
	binary.BigEndian.PutUint64(r[8:], sc.ssc)
	return r
}

func (sc *SecureCard) Prepare(header, data, le []byte) (apdu []byte, err error) {
	hc := make([]byte, len(header))
	copy(hc, header)
	hc[0] |= 0x0c

	var fedata []byte
	if data != nil {
		edata, err := sc.EncData(data)
		if err != nil {
			return nil, fmt.Errorf("Encrypting data: %w", err)
		}
		fedata = []byte{0x87, byte(len(edata) + 1), 0x01}
		fedata = append(fedata, edata...)
	}

	var fle []byte
	if le != nil {
		fle = []byte{0x97, byte(len(le))}
		fle = append(fle, le...)
	}

	phc := sc.PadData(hc)

	macData := sc.SSC()
	macData = append(macData, phc...)
	macData = append(macData, fedata...)
	macData = append(macData, fle...)

	if fedata != nil || fle != nil {
		macData = sc.PadData(macData)
	}

	macToken, err := CMAC(sc.kmac, macData)
	if err != nil {
		return nil, fmt.Errorf("MAC: %w", err)
	}
	apdu = append(apdu, hc...)
	apdu = append(apdu, byte(len(fedata)+len(fle)+2+len(macToken)))
	apdu = append(apdu, fedata...)
	apdu = append(apdu, fle...)
	apdu = append(apdu, 0x8e, byte(len(macToken)))
	apdu = append(apdu, macToken...)
	apdu = append(apdu, 0x00)

	return apdu, nil
}

func (sc *SecureCard) Process(encresp []byte) (data []byte, sw []byte, err error) {
	ptr := 0
	if encresp[ptr] == 0x87 {
		l := int(encresp[ptr+1])
		edata := encresp[ptr+3 : ptr+2+l]
		ptr += 2 + l
		data, err = sc.DecData(edata)
		if err != nil {
			return nil, nil, fmt.Errorf("Decrypt: %w", err)
		}
		data = sc.RemovePad(data)

	}
	sw = encresp[ptr+2 : ptr+4]
	ptr += 4
	macData := sc.SSC()
	macData = append(macData, encresp[0:ptr]...)
	macData = sc.PadData(macData)
	token, err := CMAC(sc.kmac, macData)
	if err != nil {
		return nil, nil, fmt.Errorf("CMAC omputation failed: %w", err)
	}
	mac := encresp[ptr+2 : ptr+10]

	if !bytes.Equal(token, mac) {
		return nil, nil, fmt.Errorf("MAC invalid")
	}
	return data, sw, nil
}

func (sc *SecureCard) EncData(data []byte) (enced []byte, err error) {
	c, err := aes.NewCipher(sc.kenc)
	if err != nil {
		return nil, fmt.Errorf("Init AES: %w", err)
	}
	aese := ecb.NewECBEncrypter(c)
	iv := sc.SSC()
	eiv := make([]byte, 16)
	aese.CryptBlocks(eiv, iv)

	aesc := cipher.NewCBCEncrypter(c, eiv)
	padded := sc.PadData(data)
	edata := make([]byte, len(padded))
	aesc.CryptBlocks(edata, padded)
	return edata, nil
}

func (sc *SecureCard) DecData(edata []byte) (data []byte, err error) {
	c, err := aes.NewCipher(sc.kenc)
	if err != nil {
		return nil, fmt.Errorf("Init AES: %w", err)
	}
	aese := ecb.NewECBEncrypter(c)
	iv := sc.SSC()
	eiv := make([]byte, 16)
	aese.CryptBlocks(eiv, iv)

	aesc := cipher.NewCBCDecrypter(c, eiv)
	data = make([]byte, len(edata))
	aesc.CryptBlocks(data, edata)
	return data, nil
}

func (sc *SecureCard) PadData(data []byte) (padded []byte) {
	padded = make([]byte, len(data))
	copy(padded, data)
	padded = append(padded, 0x80)
	pad := make([]byte, (16 - (len(padded)%16)%16))
	padded = append(padded, pad...)
	return padded
}

func (sc *SecureCard) RemovePad(data []byte) (unpadded []byte) {
	ptr := len(data) - 1
	for ; data[ptr] != 0x80; ptr-- {
	}
	return data[0:ptr]
}

func (sc *SecureCard) Transmit(header, data, le []byte) (resp []byte, err error) {
	sc.ssc++
	apdu, err := sc.Prepare(header, data, le)
	if err != nil {
		return nil, fmt.Errorf("Prepare APDU: %w", err)
	}
	resp, err = sc.card.TransmitAPDU(apdu)
	if err != nil {
		return nil, fmt.Errorf("TransmitAPDU: %w", err)
	}
	sc.ssc++
	rdata, rsw, err := sc.Process(resp)
	if err != nil {
		return nil, fmt.Errorf("Process: %w", err)
	}

	_ = rsw
	return rdata, nil
}

func (sc *SecureCard) TransmitAPDU(apdu []byte) (resp []byte, err error) {
	return nil, fmt.Errorf("Can not transmit raw APDU")
}
