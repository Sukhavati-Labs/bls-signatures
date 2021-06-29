package blsgo

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestBytesBuffer_Size
func TestBytesBuffer_Size(t *testing.T) {
	message := []byte("1234567890")
	messageLen := len(message)
	blsBytes := newBytesBufferFromBytes(message)
	blsBytesSize := blsBytes.Size()
	if blsBytesSize != messageLen {
		t.Errorf("message size:%d != blsBytes size:%d", messageLen, blsBytesSize)
		t.FailNow()
	}
	t.Logf("TestBytesBuffer_Size message size:%d == blsBytes size:%d", messageLen, blsBytesSize)
}

func TestBytesBuffer_Bytes(t *testing.T) {
	message := "123456789"
	messageBytes := []byte(message)
	buffer := newBytesBufferFromBytes(messageBytes)
	if !bytes.Equal(buffer.Bytes(), messageBytes) {
		t.Errorf("bls bytes:%s != message:%s", buffer.String(), hex.EncodeToString(messageBytes))
		t.FailNow()
	}
	t.Logf("TestBLSBytes bls bytes:%s == message:%s", buffer.String(), hex.EncodeToString(messageBytes))
}

func TestBytesBuffer_Index(t *testing.T) {
	message := "11234567890abcdefghkjlme*&)(_)+"
	messageBytes := []byte(message)
	blsBytes := newBytesBufferFromBytes(messageBytes)
	for index, c := range messageBytes {
		ch, err := blsBytes.Index(index)
		if err != nil {
			t.Errorf("TestBLSBytesIndex index:%d with error:%s", index, err)
			t.FailNow()
		}
		if c != ch {
			t.Errorf("TestBLSBytesIndex index:%d go byte:%c != bls byte :%c", index, c, ch)
			t.FailNow()
		}
	}
}

func TestNewG1ElementFromBytes(t *testing.T) {

}

func TestBasicSchemeMPL_KeyGen(t *testing.T) {
	basic := NewBasicSchemeMPL()
	seed := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	privateKey, err := basic.KeyGen(seed)
	if err != nil {
		t.FailNow()
	}
	if privateKey.IsZero() {
		t.Errorf("privateKey is zero ")
	}
	t.Log("privateKey:", privateKey.String())
	if privateKey == nil {
		t.FailNow()
	}
	publicKey, err := privateKey.GetG1Element()
	if err != nil {
		t.FailNow()
	}
	t.Log("publicKey:", publicKey.String())
}

func TestBasicSchemeMPL_PrivateKey(t *testing.T) {
	privateKeyStr := "3c53d31475bc12996a186f5173b2f63c32a23110fa44aa9415c7c2749d84be47"
	publicKeyStr := "92ebd66f33821b10060dacfd49737684a22ed41373b162f5823ccca9bb1ccdb24390c66658a4bbd6ff5781ac23936217"
	privateKeyBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		t.FailNow()
	}
	privateKey, err := NewPrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		t.FailNow()
	}
	pubKey, err := privateKey.GetG1Element()
	if err != nil {
		t.FailNow()
	}
	t.Logf("private key --> public key \nwant: %s \ngive: %s\n", publicKeyStr, pubKey.String())
	if pubKey.String() != publicKeyStr {
		t.FailNow()
	}
	privateKey2, err := NewPrivateKeyFromBytes(privateKey.Bytes())
	if err != nil {
		t.FailNow()
	}
	if privateKey2.String() != privateKeyStr {
		t.FailNow()
	}
	basic := NewBasicSchemeMPL()
	sign, err := basic.Sign(privateKey, []byte{})
	if err != nil {
		t.FailNow()
	}
	t.Log("sign:", sign.String())

}

func TestPrivateKeyAggregate(t *testing.T) {
	basic := NewBasicSchemeMPL()
	seed1 := []byte{
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
		7, 7, 7, 7, 7, 7, 7, 7,
	}
	seed2 := []byte{
		1, 2, 3, 4, 5, 6, 7, 2,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	seed3 := []byte{
		1, 2, 3, 4, 5, 6, 7, 3,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	privateKey1, err := basic.KeyGen(seed1)
	if err != nil {
		t.Error("privateKey1 seed fail", err)
		t.FailNow()
	}
	privateKey1FromBytes, err := NewPrivateKeyFromBytes(privateKey1.Bytes())
	if err != nil {
		t.Error("privateKey1 seed fail", err)
		t.FailNow()
	}
	if privateKey1FromBytes.String() != privateKey1.String() {
		t.Error("privateKey1 fail")
		t.FailNow()
	}

	privateKey2, err := basic.KeyGen(seed2)
	if err != nil {
		t.Error("privateKey2 fail", err)
		t.FailNow()
	}
	t.Log("privateKey2:", privateKey2.String())
	privateKey3, err := basic.KeyGen(seed3)
	if err != nil {
		t.Error("privateKey3 fail", err)
		t.FailNow()
	}
	message := []byte{1, 2, 3}
	t.Log("privateKey3:", privateKey3.String())
	augKey12,err := PrivateKeyAggregate([]*PrivateKey{privateKey1, privateKey2})
	if err != nil {
		t.FailNow()
	}
	t.Log("augKey12:", augKey12.String())
	pubKey12, err := augKey12.GetG1Element()
	if err != nil {
		t.Error("privateKey12 fail", err)
		t.FailNow()
	}
	t.Log("pubKey12:", pubKey12.String())
	sign, err := basic.Sign(privateKey1, message)
	if err != nil {
		t.Error("sign fail", err)
		t.FailNow()
	}
	t.Log("sign:", sign.String())
	publicKey1, err := privateKey1.GetG1Element()
	if err != nil {
		t.Error("sign fail", err)
		t.FailNow()
	}
	t.Log("publicKey:", publicKey1)
	ok, err := basic.Verify(publicKey1, message, sign)
	if err != nil {
		t.Error("sign fail", err)
		t.FailNow()
	}
	if !ok {
		t.Error("sign fail", err)
		t.FailNow()
	}
	augKey123 ,err:= PrivateKeyAggregate([]*PrivateKey{augKey12, privateKey3})
	if err != nil {
		t.FailNow()
	}
	t.Log("augKey123:", augKey123.String())
	augKey3 ,err:= PrivateKeyAggregate([]*PrivateKey{privateKey1, privateKey2, privateKey3})
	if err != nil {
		t.FailNow()
	}
	t.Log("augKey:", augKey3.String())
	if augKey123.String() != augKey3.String() {
		t.FailNow()
	}
}

func TestAugSchemeMPL_AggregatePublicKeys(t *testing.T) {

}

func TestG1Element_GetFingerprint(t *testing.T){
    publicKeyBytes,err := hex.DecodeString("a60a1b6a2eece9575eda4e5eba4408b0eae4213f55e0a6560a9d826a8340a6f4c2d0c956803d756269d5fc25c898f9db")
    if err != nil {
        t.FailNow()
    }
	publicKey, err := NewG1ElementFromBytes(publicKeyBytes)
	if err != nil {
		t.FailNow()
	}
	fingerprint,err := publicKey.GetFingerprint()
	if err != nil {
		t.FailNow()
	}
	var fingerprintWant uint32  =1010781798
	t.Log("fingerprint:",fingerprint)
	t.Log("want fingerprint:",fingerprintWant)
	if fingerprint != fingerprintWant {
		t.FailNow()
	}

}

func TestAugSchemeMPL_DeriveChildSk(t *testing.T) {
	privateKeyBytes, err := hex.DecodeString("007259d0b6faf4478c2461e372aae59cea4ed4d4fc3e3668fc061df6cd000729")

	if err != nil {
		t.FailNow()
	}
	publicKeyBytes, err := hex.DecodeString("b785108ae0cb2d4c34376d3ed93174a237d0d582a308f4778d5bbe95351703372dfaac2f155aefedac603f0ca88e11af")
	if err != nil {
		t.FailNow()
	}
	privateKey, err := NewPrivateKeyFromBytes(privateKeyBytes)
	t.Log("sk0:", privateKey.String())
	mpl := NewAugSchemeMPL()
	sk1, err := mpl.DeriveChildSk(privateKey, 12381)
	if err != nil {
		t.FailNow()
	}
	t.Log("sk1:", sk1.String())
	sk2, err := mpl.DeriveChildSk(sk1, 8444)
	if err != nil {
		t.FailNow()
	}
	t.Log("sk2:", sk2.String())
	sk3, err := mpl.DeriveChildSk(sk2, 0)
	if err != nil {
		t.FailNow()
	}
	t.Log("sk3:", sk3.String())
	sk4, err := mpl.DeriveChildSk(sk3, 0)
	if err != nil {
		t.FailNow()
	}
	// 52d4341dfbe7eac0d10ebdc76d91d5f6536c9dbb1ce1423d5785f79874226099
	t.Log("sk4:", sk4.String())
	pk4, err := sk4.GetG1Element()
	if err != nil {
		t.FailNow()
	}
	t.Log("pk4:", pk4.String())
	if !bytes.Equal(pk4.Bytes(), publicKeyBytes) {
		t.FailNow()
	}
}

func DerivePath(sk *PrivateKey, path []int) (privateKey *PrivateKey, err error) {
	privateKey = sk
	mpl := NewAugSchemeMPL()
	for _, index := range path {
		privateKey, err = mpl.DeriveChildSk(privateKey, uint32(index))
		if err != nil {
			return nil, err
		}
	}
	return privateKey, nil
}

func TestDerivePath(t *testing.T){
	farmerKeyBytes, err := hex.DecodeString("b785108ae0cb2d4c34376d3ed93174a237d0d582a308f4778d5bbe95351703372dfaac2f155aefedac603f0ca88e11af")
	if err != nil {
		t.FailNow()
	}
	privateKeyBytes, err := hex.DecodeString("007259d0b6faf4478c2461e372aae59cea4ed4d4fc3e3668fc061df6cd000729")

	if err != nil {
		t.FailNow()
	}
	privateKey, err := NewPrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		t.FailNow()
	}

	farmerPrivateKey, err := DerivePath(privateKey, []int{12381, 8444, 0, 0})
	if err != nil {
		t.FailNow()
	}
	farmerPublicKey, err := farmerPrivateKey.GetG1Element()
	if err != nil {
		t.FailNow()
	}
	if !bytes.Equal(farmerKeyBytes, farmerPublicKey.Bytes()) {
		t.FailNow()
	}
}

func TestBasicSchemeMPL_Sign(t *testing.T){
	mpl := NewAugSchemeMPL()
	seed := []byte{
		1,2,3,4,5,6,7,8,
		1,2,3,4,5,6,7,8,
		1,2,3,4,5,6,7,8,
		1,2,3,4,5,6,7,8,
	}
	privateKey, err := mpl.KeyGen(seed)
	if err != nil {
		t.FailNow()
	}
	sign, err := mpl.Sign(privateKey, seed)
	if err != nil {
		t.FailNow()
	}
	t.Log("sign:",sign.String())
	publicKey, err := privateKey.GetG1Element()
	if err != nil {
		t.FailNow()
	}
	prependingSign, err := mpl.PrependingSign(privateKey, seed, publicKey)
	if err != nil {
		t.FailNow()
	}
	t.Log("prependingSign:",sign.String())
	if !sign.IsEqual(prependingSign){
		t.FailNow()
	}
}


