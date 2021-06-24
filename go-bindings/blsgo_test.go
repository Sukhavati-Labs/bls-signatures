package blsgo

import (
	"bytes"
	"encoding/hex"
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
	println(hex.EncodeToString(privateKey.Bytes()))
	if privateKey == nil {
		t.FailNow()
	}
}

func TestPrivateKeyAggregate(t *testing.T) {
	basic := NewBasicSchemeMPL()
	seed1 := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	seed2 := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	seed3 := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	privateKey1, err := basic.KeyGen(seed1)
	if err != nil {
		t.FailNow()
	}
	println("privateKey1:%s", hex.EncodeToString(privateKey1.Bytes()))
	privateKey2, err := basic.KeyGen(seed2)
	if err != nil {
		t.FailNow()
	}
	println("privateKey2:%s", hex.EncodeToString(privateKey2.Bytes()))
	privateKey3, err := basic.KeyGen(seed3)
	if err != nil {
		t.FailNow()
	}
	println("privateKey3:%s", hex.EncodeToString(privateKey3.Bytes()))
	keys := []*PrivateKey{privateKey1, privateKey2, privateKey3}
	augKey := PrivateKeyAggregate(keys)
	println("augKey:%s", hex.EncodeToString(augKey.Bytes()))
}
