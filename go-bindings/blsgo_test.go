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
       t.Errorf("message size:%d != blsBytes size:%d",messageLen,blsBytesSize)
       t.FailNow()
    }
    t.Logf("TestBLSBytesSize message size:%d == blsBytes size:%d",messageLen,blsBytesSize)
}

func TestBLSBytes(t *testing.T){
    message := "123456789"
    messageBytes := []byte(message)
    blsBytes := NewBLSBytesFromBytes(messageBytes)
    blsBytesBytes := blsBytes.Bytes()
    if !bytes.Equal(blsBytes.Bytes(),messageBytes) {
        t.Errorf("bls bytes:%s != message:%s",hex.EncodeToString(blsBytesBytes),hex.EncodeToString(messageBytes))
        t.FailNow()
    }
    t.Logf("TestBLSBytes bls bytes:%s == message:%s",hex.EncodeToString(blsBytesBytes),hex.EncodeToString(messageBytes))
}