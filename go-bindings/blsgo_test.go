package blsgo

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBLSBytesSize(t *testing.T) {
	message := []byte("1234567890")
	messageLen := len(message)
	blsBytes := NewBLSBytesFromBytes(message)
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
