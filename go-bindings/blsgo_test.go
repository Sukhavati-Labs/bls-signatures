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
		t.Errorf("bls bytes:%s != message:%s",buffer.String(),hex.EncodeToString(messageBytes))
		t.FailNow()
	}
	t.Logf("TestBLSBytes bls bytes:%s == message:%s",buffer.String(), hex.EncodeToString(messageBytes))
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
	publicKey ,err:= privateKey.GetG1Element()
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
	privateKey,err := NewPrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		t.FailNow()
	}
	pubKey ,err:= privateKey.GetG1Element()
	if err != nil {
		t.FailNow()
	}
	t.Logf("private key --> public key \nwant: %s \ngive: %s\n", publicKeyStr, pubKey.String())
	if pubKey.String() != publicKeyStr {
		t.FailNow()
	}
	privateKey2,err := NewPrivateKeyFromBytes(privateKey.Bytes())
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
		t.Error("privateKey1 seed fail",err)
		t.FailNow()
	}
	privateKey1FromBytes,err := NewPrivateKeyFromBytes(privateKey1.Bytes())
	if err != nil {
		t.Error("privateKey1 seed fail",err)
		t.FailNow()
	}
	if privateKey1FromBytes.String() != privateKey1.String() {
		t.Error("privateKey1 fail")
		t.FailNow()
	}

	privateKey2, err := basic.KeyGen(seed2)
	if err != nil {
		t.Error("privateKey2 fail",err)
		t.FailNow()
	}
	t.Log("privateKey2:", privateKey2.String())
	privateKey3, err := basic.KeyGen(seed3)
	if err != nil {
		t.Error("privateKey3 fail",err)
		t.FailNow()
	}
	message := []byte{1, 2, 3}
	t.Log("privateKey3:", privateKey3.String())
	augKey12 := PrivateKeyAggregate([]*PrivateKey{privateKey1, privateKey2})
	t.Log("augKey12:", augKey12.String())
	pubKey12,err := augKey12.GetG1Element()
	if err != nil {
		t.Error("privateKey12 fail",err)
		t.FailNow()
	}
	t.Log("pubKey12:", pubKey12.String())
	sign, err := basic.Sign(privateKey1, message)
	if err != nil {
		t.Error("sign fail",err)
		t.FailNow()
	}
	t.Log("sign:", sign.String())
	publicKey1,err := privateKey1.GetG1Element()
	if err != nil {
		t.Error("sign fail",err)
		t.FailNow()
	}
	t.Log("publicKey:", publicKey1)
	ok,err:=basic.Verify(publicKey1, message, sign)
	if err != nil {
		t.Error("sign fail",err)
		t.FailNow()
	}
	if !ok {
		t.Error("sign fail",err)
		t.FailNow()
	}
	augKey123 := PrivateKeyAggregate([]*PrivateKey{augKey12, privateKey3})
	t.Log("augKey123:", augKey123.String())
	augKey3 := PrivateKeyAggregate([]*PrivateKey{privateKey1, privateKey2, privateKey3})
	t.Log("augKey:", augKey3.String())
	if augKey123.String() != augKey3.String() {
		t.FailNow()
	}
}
