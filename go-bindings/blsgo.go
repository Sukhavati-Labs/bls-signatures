package blsgo

/*
#cgo CFLAGS: -I ../build/_deps/relic-build/include
#cgo CFLAGS: -I ../build/_deps/relic-src/include
#cgo CFLAGS: -I ../build/go-bindings
#cgo CXXFLAGS: -I ../build/_deps/relic-src/include
#cgo CXXFLAGS: -I ../build/go-bindings
#cgo CXXFLAGS: -I ../build/_deps/relic-build/include
#cgo darwin CXXFLAGS: -I /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/c++/v1
#cgo linux LDFLAGS: -L/usr/lib
#cgo darwin LDFLAGS: -L/usr/lib
#cgo LDFLAGS: -L ../build/_deps/relic-build/lib
#cgo LDFLAGS: -L ../build
#cgo LDFLAGS: -L ../build/src
#cgo LDFLAGS: -L ../build/go-bindings
#cgo LDFLAGS: -lstdc++ -lbls -lblstmp -lblsgo -lrelic_s
#include "gobindings.h"
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"unsafe"
)

func bytesToCUint8Bytes(buffer []byte) (*C.uint8_t, C.size_t) {
	size := len(buffer)
	cBuffer := (*C.uint8_t)(C.CBytes(buffer))
	return cBuffer, C.size_t(size)
}

// BLSBytes bls bytes wrapper
type BLSBytes struct {
	instance C.BytesWrapper
}

func NewBLSBytesFromBytesWrapper(byteWrapper C.BytesWrapper) *BLSBytes {
	blsBytes := &BLSBytes{
		instance: byteWrapper,
	}
	return blsBytes
}

func NewBLSBytesFromBytes(buffer []byte) *BLSBytes {
	cBuffer, size := bytesToCUint8Bytes(buffer)
	defer C.free(unsafe.Pointer(cBuffer))
	blsBytes := &BLSBytes{
		instance: C.BytesWrapperInit(cBuffer, size),
	}
	return blsBytes
}

func (b *BLSBytes) Instance() C.BytesWrapper {
	return b.instance
}

func (b *BLSBytes) Free() {
	C.BytesWrapperFree(b.instance)
}

func (b *BLSBytes) Size() int {
	return int(C.BytesWrapperSize(b.instance))
}

func (b *BLSBytes) Bytes() []byte {
	begin := C.BytesWrapperBegin(b.instance)
	size := C.BytesWrapperSize(b.instance)
	return C.GoBytes(unsafe.Pointer(begin), C.int(size))
}

func (b *BLSBytes) Index(index int) (byte, error) {
	if index < 0 {
		return 0, fmt.Errorf("The index must be positive ")
	}
	size := C.BytesWrapperSize(b.instance)
	if index > int(size) {
		return 0, fmt.Errorf("Out of the scope of the index ")
	}
	c := C.BytesWrapperIndex(b.instance, C.int(index))
	return byte(c), nil
}

func (b *BLSBytes) String() string {
	return hex.EncodeToString(b.Bytes())
}

// PrivateKey private key
type PrivateKey struct {
	instance C.PrivateKeyWrapper
}

func NewPrivateKeyFromBytes(bytes []byte) *PrivateKey {
	cBuffer, size := bytesToCUint8Bytes(bytes)
	defer C.free(unsafe.Pointer(cBuffer))
	privateKey := &PrivateKey{
		instance: C.PrivateKeyWrapperFromBytes(cBuffer, size),
	}
	return privateKey
}

func (sk *PrivateKey) IsZero() bool {
	zero := C.PrivateKeyWrapperIsZero(sk.instance)
	return zero == 1
}

func (sk *PrivateKey) Bytes() []byte {
	b := C.PrivateKeyWrapperSerialize(sk.instance)
	buffer := NewBLSBytesFromBytesWrapper(b)
	return buffer.Bytes()
}

func (sk *PrivateKey) String() string {
	return hex.EncodeToString(sk.Bytes())
}

func (sk *PrivateKey) IsEqual(key *PrivateKey) bool {
	return bytes.Equal(sk.Bytes(), key.Bytes())
}

func (sk *PrivateKey) GetG1Element() *G1Element {
	g1 := C.PrivateKeyWrapperGetG1Element(sk.instance)
	return &G1Element{
		publicKey: NewBLSBytesFromBytesWrapper(g1),
	}
}

func PrivateKeyAggregate(privateKeys []*PrivateKey) *PrivateKey {
	num := len(privateKeys)
	privKeys := make([]C.PrivateKeyWrapper, num)
	for i, k := range privateKeys {
		privKeys[i] = (*k).instance
	}
	augKey := C.PrivateKeyWrapperAggregate((*C.PrivateKeyWrapper)(unsafe.Pointer(&privKeys[0])), C.int(num))
	return &PrivateKey{
		instance: augKey,
	}
}

//G1Element g1 element
type G1Element struct {
	publicKey *BLSBytes
}

func NewG1ElementFromBytes(buffer []byte) *G1Element {
	bytes := NewBLSBytesFromBytes(buffer)
	return &G1Element{
		publicKey: bytes,
	}
}

func (g1 *G1Element) Bytes() []byte {
	return g1.publicKey.Bytes()
}
func (g1 *G1Element) BLSBytes() C.BytesWrapper {
	return g1.publicKey.Instance()
}

func (g1 *G1Element) IsEqual(element *G1Element) bool {
	return bytes.Equal(g1.Bytes(), element.Bytes())
}

func (g1 *G1Element) Size() int {
	return g1.publicKey.Size()
}
func (g1 *G1Element) Free() {

}

func (g1 *G1Element) String() string {
	return hex.EncodeToString(g1.publicKey.Bytes())
}

type G2Element struct {
	//instance C.G2ElementWrapper
	signature *BLSBytes
}

func NewG2ElementFromBytes(buffer []byte) *G2Element {
	bytes := NewBLSBytesFromBytes(buffer)
	return &G2Element{
		signature: bytes,
	}
}

func (g2 *G2Element) Bytes() []byte {
	return g2.signature.Bytes()
}

func (g2 *G2Element) Size() int {
	return g2.signature.Size()
}

func (g2 *G2Element) BLSBytes() C.BytesWrapper {
	return g2.signature.Instance()
}

func (g2 *G2Element) IsEqual(element *G2Element) bool {
	return bytes.Equal(g2.Bytes(), element.Bytes())
}

func (g2 *G2Element) Free() {

}

func (g2 *G2Element) String() string {
	return hex.EncodeToString(g2.signature.Bytes())
}

type BasicSchemeMPL struct {
	instance C.BasicSchemeMPLWrapper
}

func (bs *BasicSchemeMPL) Aggregate(publicKeys []*G1Element) (*G1Element, error) {
	num := len(publicKeys)
	pubKeys := make([]C.BytesWrapper, num)
	for i, k := range publicKeys {
		pubKeys[i] = k.publicKey.instance
	}
	augKey := C.BasicSchemeMPLWrapperAggregateG1Element(bs.instance, (*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(num))
	return &G1Element{
		publicKey: NewBLSBytesFromBytesWrapper(augKey),
	}, nil
}

func (bs *BasicSchemeMPL) Sign(privateKey *PrivateKey, message []byte) (*G2Element, error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	sig := C.BasicSchemeMPLWrapperSign(bs.instance, privateKey.instance, cBuffer, size)
	g2 := &G2Element{
		signature: NewBLSBytesFromBytesWrapper(sig),
	}
	return g2, nil
}

func (bs *BasicSchemeMPL) Verify(publicKey *G1Element, message []byte, signature *G2Element) bool {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ok := C.BasicSchemeMPLWrapperVerify(bs.instance, publicKey.BLSBytes(), cBuffer, size, signature.BLSBytes())
	return ok > 0
}

func NewBasicSchemeMPL() *BasicSchemeMPL {
	basicSchemeWrapper := C.BasicSchemeMPLWrapperInit()
	basicScheme := &BasicSchemeMPL{
		instance: basicSchemeWrapper,
	}
	return basicScheme
}

func (bs *BasicSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	cBuffer, size := bytesToCUint8Bytes(seed)
	defer C.free(unsafe.Pointer(cBuffer))
	if size < 32 {
		return nil, fmt.Errorf("seed size must >= 32")
	}
	var privateKeyWrapper C.PrivateKeyWrapper = C.BasicSchemeMPLWrapperGenKey(bs.instance, cBuffer, C.size_t(size))
	privateKey := &PrivateKey{
		instance: privateKeyWrapper,
	}
	return privateKey, nil
}

type AugSchemeMPL struct {
	instance C.AugSchemeMPLWrapper
}

func NewAugSchemeMPL() *AugSchemeMPL {
	augSchemeWrapper := C.AugSchemeMPLWrapperInit()
	augScheme := &AugSchemeMPL{
		instance: augSchemeWrapper,
	}
	return augScheme
}
