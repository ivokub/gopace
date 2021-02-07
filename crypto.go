package gopace

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/jacobsa/crypto/cmac"
)

func DecryptNonce(can []byte, encNonce []byte) (decNonce []byte, err error) {
	prekey := append(can, 0x00, 0x00, 0x00, 0x03)
	key := sha256.Sum256(prekey)
	var iv [16]byte
	aesBlock, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("Init AES: %w", err)
	}
	aesCbc := cipher.NewCBCDecrypter(aesBlock, iv[:])
	decNonce = make([]byte, len(encNonce))
	aesCbc.CryptBlocks(decNonce, encNonce)
	return decNonce, nil
}

func TerminalKeyMap(sk []byte) (x, y []byte, err error) {
	p256 := elliptic.P256()
	xB, yB := p256.ScalarBaseMult(sk)
	x = xB.Bytes()
	y = yB.Bytes()
	return x, y, nil
}

func SharedPoint(x, y, sk []byte) (sx, sy []byte) {
	p256 := elliptic.P256()
	xB := new(big.Int).SetBytes(x)
	yB := new(big.Int).SetBytes(y)
	sxB, syB := p256.ScalarMult(xB, yB, sk)
	sx = sxB.Bytes()
	sy = syB.Bytes()
	return sx, sy
}

func MappedBasePoint(decNonce []byte, sx, sy []byte) (mx, my []byte) {
	p256 := elliptic.P256()
	ax, ay := p256.ScalarBaseMult(decNonce)
	sxB := new(big.Int).SetBytes(sx)
	syB := new(big.Int).SetBytes(sy)
	mxB, myB := p256.Add(ax, ay, sxB, syB)
	mx = mxB.Bytes()
	my = myB.Bytes()
	return mx, my
}

func MappedPublicKey(sk2 []byte, mx, my []byte) (msx, msy []byte) {
	p256 := elliptic.P256()
	mxB := new(big.Int).SetBytes(mx)
	myB := new(big.Int).SetBytes(my)
	msxB, msyB := p256.ScalarMult(mxB, myB, sk2)
	msx = msxB.Bytes()
	msy = msyB.Bytes()
	return msx, msy
}

func MappedECDH(sk2 []byte, msx, msy []byte) (smsx, smsy []byte) {
	p256 := elliptic.P256()
	msxB := new(big.Int).SetBytes(msx)
	msyB := new(big.Int).SetBytes(msy)
	smsxB, smsyB := p256.ScalarMult(msxB, msyB, sk2)
	smsx = smsxB.Bytes()
	smsy = smsyB.Bytes()
	return smsx, smsy
}

func SessionKeys(smsx []byte) (kenc, kmac []byte) {
	prekenc := append(smsx, 0x00, 0x00, 0x00, 0x01)
	kencb := sha256.Sum256(prekenc)
	prekmac := append(smsx, 0x00, 0x00, 0x00, 0x02)
	kmacb := sha256.Sum256(prekmac)
	return kencb[:], kmacb[:]
}

func ComputeAuthenticationToken(deroid, msx, msy []byte) []byte {
	data := []byte{0x7f, 0x49}
	m := MarshalECPoint(msx, msy)
	data = append(data, byte(len(deroid)+len(m)+4))
	data = append(data, 0x06, byte(len(deroid)))
	data = append(data, deroid...)
	data = append(data, 0x86, byte(len(m)))
	data = append(data, m...)
	return data
}

func CMAC(kmac []byte, data []byte) (mac []byte, err error) {
	h, err := cmac.New(kmac)
	if err != nil {
		return nil, fmt.Errorf("AES-CMAC init failed: %w", err)
	}
	h.Write(data)
	mac = h.Sum(nil)
	return mac[:8], nil
}

func MarshalECPoint(x, y []byte) []byte {
	m := []byte{0x04}
	m = append(m, x...)
	m = append(m, y...)
	return m
}

func UnmarshalECPoint(m []byte) (x, y []byte) {
	p256 := elliptic.P256()
	xb, yb := elliptic.Unmarshal(p256, m)
	x = xb.Bytes()
	y = yb.Bytes()
	return x, y
}
