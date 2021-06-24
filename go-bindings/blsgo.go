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
	"encoding/hex"
	"fmt"
	"unsafe"
)

// BLSBytes bls bytes wrapper
type BLSBytes struct {
	instance C.BytesWrapper
}

func NewBLSBytesFromBytes(buffer []byte) *BLSBytes {
	size := len(buffer)
	cBuffer := (*C.uint8_t)(C.CBytes(buffer))
	blsBytes := &BLSBytes{
		instance: C.BytesWrapperInit(cBuffer, C.size_t(size)),
	}
	C.free(unsafe.Pointer(cBuffer))
	return blsBytes
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

func (sk *PrivateKey) IsZero() bool {
	zero := C.PrivateKeyWrapperIsZero(sk.instance)
	return zero == 1
}

func (sk *PrivateKey) Bytes() []byte {
	b := unsafe.Pointer(C.PrivateKeyWrapperSerialize(sk.instance))
	defer C.free(b)
	return C.GoBytes(b, C.int(32))
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
	instance C.G1ElementWrapper
}

func NewG1ElementFromBytes(buffer []byte) *G1Element {
	size := len(buffer)
	cBuffer := (*C.uint8_t)(C.CBytes(buffer))
	g1 := &G1Element{
		instance: C.G1ElementWrapperFromBytes(cBuffer, C.size_t(size)),
	}
	return g1
}

type G2Element struct {
	instance C.G2ElementWrapper
}

type BasicSchemeMPL struct {
	instance C.BasicSchemeMPLWrapper
}

func NewBasicSchemeMPL() *BasicSchemeMPL {
	basicSchemeWrapper := C.BasicSchemeMPLWrapperInit()
	basicScheme := &BasicSchemeMPL{
		instance: basicSchemeWrapper,
	}
	return basicScheme
}

func (bs *BasicSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	size := len(seed)
	if size < 32 {
		return nil, fmt.Errorf("seed size must >= 32")
	}
	cBuffer := (*C.uint8_t)(C.CBytes(seed))
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
