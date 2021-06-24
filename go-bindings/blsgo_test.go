package blsgo

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// TTestBLSBytesSize
func TestBLSBytesSize(t *testing.T) {
	message := []byte("1234567890")
	messageLen := len(message)
	blsBytes := NewBLSBytesFromBytes(message)
	defer blsBytes.Free()
	blsBytesSize := blsBytes.Size()
	if blsBytesSize != messageLen {
		t.Errorf("message size:%d != blsBytes size:%d", messageLen, blsBytesSize)
		t.FailNow()
	}
	t.Logf("TestBLSBytesSize message size:%d == blsBytes size:%d", messageLen, blsBytesSize)
}

func TestBLSBytes(t *testing.T) {
	message := "123456789"
	messageBytes := []byte(message)
	blsBytes := NewBLSBytesFromBytes(messageBytes)
	blsBytesBytes := blsBytes.Bytes()
	if !bytes.Equal(blsBytes.Bytes(), messageBytes) {
		t.Errorf("bls bytes:%s != message:%s", hex.EncodeToString(blsBytesBytes), hex.EncodeToString(messageBytes))
		t.FailNow()
	}
	t.Logf("TestBLSBytes bls bytes:%s == message:%s", hex.EncodeToString(blsBytesBytes), hex.EncodeToString(messageBytes))
}

func TestBLSBytesIndex(t *testing.T) {
	message := "11234567890abcdefghkjlme*&)(_)+"
	messageBytes := []byte(message)
	blsBytes := NewBLSBytesFromBytes(messageBytes)
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
	println("privateKey:",privateKey.String())
	if privateKey == nil {
		t.FailNow()
	}
	publicKey := privateKey.GetG1Element()
	println("publicKey:",publicKey.String())
}

func TestBasicSchemeMPL_PrivateKey(t *testing.T){
    privateKeyStr:="3c53d31475bc12996a186f5173b2f63c32a23110fa44aa9415c7c2749d84be47"
    publicKeyStr := "92ebd66f33821b10060dacfd49737684a22ed41373b162f5823ccca9bb1ccdb24390c66658a4bbd6ff5781ac23936217"
	privateKeyBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		t.FailNow()
	}
	privateKey := NewPrivateKeyFromBytes(privateKeyBytes)
	pubKey := privateKey.GetG1Element()
	fmt.Printf("private key --> public key \nwant: %s \ngive: %s\n",publicKeyStr,pubKey.String() )
	if pubKey.String() != publicKeyStr {
		t.FailNow()
	}
	privateKey2 := NewPrivateKeyFromBytes(privateKey.Bytes())
	if privateKey2.String() != privateKeyStr {
		t.FailNow()
	}

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
		t.FailNow()
	}
	privateKey1FromBytes := NewG1ElementFromBytes(privateKey1.Bytes())
	if privateKey1FromBytes.String() != privateKey1.String() {
		t.FailNow()
	}
	println("privateKey1:", privateKey1.String())
	println("publicKey1:",privateKey1.GetG1Element().String())
	privateKey2, err := basic.KeyGen(seed2)
	if err != nil {
		t.FailNow()
	}
	println("privateKey2:", privateKey2.String())
	privateKey3, err := basic.KeyGen(seed3)
	if err != nil {
		t.FailNow()
	}
	message := []byte{1,2,3}
	println("privateKey3:",privateKey3.String())
	augKey12 := PrivateKeyAggregate([]*PrivateKey{privateKey1,privateKey2})
	println("augKey12:",augKey12.String())
	pubKey12 := augKey12.GetG1Element()
	println("pubKey12:",pubKey12.String())
	sign, err := basic.Sign(privateKey1, message)
	if err != nil {
	   t.FailNow()
	}
	println("----------------------------------------------")
	println("sign:",sign.String())
	println("publicKey:",privateKey1.GetG1Element().String())
// 	for i:=0;i<100;i++{
// 		sign, _ := basic.Sign(privateKey1, message)
// 		println("sign:",sign.String())
// 		println("publicKey:",privateKey1.GetG1Element().String())
// 		println("sign:",sign.String())
// 	}
	if !basic.Verify(privateKey1.GetG1Element(),message,sign) {
		println("verify fail")
		t.FailNow()
	}
	augKey123 := PrivateKeyAggregate([]*PrivateKey{augKey12,privateKey3})
	println("augKey123:",augKey123.String())
	augKey3 := PrivateKeyAggregate([]*PrivateKey{privateKey1, privateKey2, privateKey3})
	println("augKey:", augKey3.String())
	if augKey123.String() != augKey3.String() {
	   t.FailNow()
	}
}
