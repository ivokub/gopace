package main

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
)

var (
	cardAccessEF         = []byte{0x01, 0x1c}
	apduSetAT            = []byte{0x00, 0x22, 0xc1, 0xa4}
	getNonce             = []byte{0x10, 0x86, 0x00, 0x00}
	mapNonce             = []byte{0x10, 0x86, 0x00, 0x00}
	performKeyAgreement  = []byte{0x10, 0x86, 0x00, 0x00}
	mutualAuthentication = []byte{0x00, 0x86, 0x00, 0x00}
)

type PersonalInfoSET []PersonalInfo

type PersonalInfo struct {
	Protocol    asn1.RawValue
	Version     int
	ParameterID int
}

func ReadCardAccess(card *PlainCard) (pi *PersonalInfo, err error) {
	err = SelectFile(card, cardAccessEF)
	if err != nil {
		return nil, err
	}
	content, err := ReadBinary(card)
	var pis PersonalInfoSET
	_, err = asn1.Unmarshal(content, &pis)
	if err != nil {
		return nil, fmt.Errorf("Unmarshalling: %w", err)
	}
	if len(pis) != 1 {
		return nil, fmt.Errorf("Invalid PrivateInfoSET length")
	}
	return &(pis[0]), nil
}

func SetAuthenticationTemplate(card *PlainCard, pi *PersonalInfo) (err error) {
	deroid := pi.Protocol.Bytes
	derdata := append([]byte{0x80, byte(len(deroid))}, deroid...)
	candata := []byte{0x83, 0x01, 0x02}
	data := append(derdata, candata...)
	fmt.Println("== SetAT")
	if _, err = card.Transmit(apduSetAT, data, []byte{0x00}); err != nil {
		return fmt.Errorf("SetAT: %w", err)
	}
	return nil
}

func GetNonce(card *PlainCard) (encNonce []byte, err error) {
	fmt.Println("== Get Nonce")
	resp, err := card.Transmit(getNonce, []byte{0x7c, 0x00}, []byte{0x00})
	if err != nil {
		return nil, fmt.Errorf("Transmit GET NONCE: %w", err)
	}
	if len(resp) <= 4 {
		return nil, fmt.Errorf("Short nonce: %d", len(resp))
	}
	encNonce = resp[4:]
	return encNonce, nil
}

func MapNonce(card *PlainCard, x, y []byte) (x2, y2 []byte, err error) {
	m := MarshalECPoint(x, y)
	data := []byte{0x7c, byte(len(m) + 2), 0x81, byte(len(m))}
	data = append(data, m...)
	fmt.Println("== Map Nonce")
	resp, err := card.Transmit(mapNonce, data, []byte{0x00})
	if err != nil {
		return nil, nil, fmt.Errorf("Transmit Map Nonce: %v", err)
	}
	mm := resp[4:]
	x2, y2 = UnmarshalECPoint(mm)
	return x2, y2, nil
}

func PerformKeyAgreement(card *PlainCard, msx, msy []byte) (msx2, msy2 []byte, err error) {
	m := MarshalECPoint(msx, msy)
	data := []byte{0x7c, byte(len(m) + 2), 0x83, byte(len(m))}
	data = append(data, m...)
	fmt.Println("== Perform Key Agreement")
	resp, err := card.Transmit(performKeyAgreement, data, []byte{0x00})
	if err != nil {
		return nil, nil, fmt.Errorf("Transmit Perform Key Agreement: %v", err)
	}
	mm := resp[4:]
	msx2, msy2 = UnmarshalECPoint(mm)
	return msx2, msy2, nil
}

func MutualAuthentication(card Carder, tcmac, ccmac []byte) error {
	data := []byte{0x7c, byte(len(tcmac) + 2), 0x85, byte(len(tcmac))}
	data = append(data, tcmac...)
	fmt.Println("== Mutual Authentication")
	resp, err := card.Transmit(mutualAuthentication, data, []byte{0x00})
	if err != nil {
		return fmt.Errorf("Transmit Mutual Authentication: %v", err)
	}
	respcmac := resp[4:]
	if !bytes.Equal(respcmac, ccmac) {
		return fmt.Errorf("CMAC compare failed: %x %x", respcmac, ccmac)
	}
	return nil
}

func PACE(card *PlainCard, can []byte) (seccard *SecureCard, err error) {
	pi, err := ReadCardAccess(card)
	if err != nil {
		return nil, fmt.Errorf("Read card access: %w", err)
	}
	if err = SetAuthenticationTemplate(card, pi); err != nil {
		return nil, fmt.Errorf("Set AT: %w", err)
	}
	encNonce, err := GetNonce(card)
	if err != nil {
		return nil, fmt.Errorf("Get Nonce: %w", err)
	}
	decNonce, err := DecryptNonce(can, encNonce)
	if err != nil {
		return nil, fmt.Errorf("Decrypt nonce: %w", err)
	}
	sk1 := make([]byte, 32)
	sk2 := make([]byte, 32)
	rand.Read(sk1)
	rand.Read(sk2)
	x, y, err := TerminalKeyMap(sk1)
	if err != nil {
		return nil, fmt.Errorf("Terminal Key Map: %w", err)
	}
	x2, y2, err := MapNonce(card, x, y)
	if err != nil {
		return nil, fmt.Errorf("Map nonce: %w", err)
	}
	sx, sy := SharedPoint(x2, y2, sk1)
	mx, my := MappedBasePoint(decNonce, sx, sy)
	msx, msy := MappedPublicKey(sk2, mx, my)
	msx2, msy2, err := PerformKeyAgreement(card, msx, msy)
	if err != nil {
		return nil, fmt.Errorf("Perform Key agreement: %w", err)
	}
	smsx, _ := MappedECDH(sk2, msx2, msy2)
	kenc, kmac := SessionKeys(smsx)
	tauth := ComputeAuthenticationToken(pi.Protocol.Bytes, msx2, msy2)
	cauth := ComputeAuthenticationToken(pi.Protocol.Bytes, msx, msy)
	tcmac, err := CMAC(kmac, tauth)
	if err != nil {
		return nil, fmt.Errorf("Terminal CMAC failed: %w", err)
	}
	ccmac, err := CMAC(kmac, cauth)
	if err != nil {
		return nil, fmt.Errorf("Card CMAC failed: %w", err)
	}
	if err = MutualAuthentication(card, tcmac, ccmac); err != nil {
		return nil, fmt.Errorf("Mutual Auth failed: %w", err)
	}
	return &SecureCard{kenc, kmac, 0, card}, nil
}
