package blsgo

/*
#cgo CFLAGS: -I ../build/_deps/relic-build/include
#cgo CXXFLAGS: -I ../build/_deps/relic-src/include -I ../build/go-bindings -I ../build/_deps/relic-build/include  -I /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/c++/v1
#cgo darwin LDFLAGS: -L/usr/lib  -L ../build/go-bindings -lstdc++ -lblsgo
#include "gobindings.h"
#include <stdlib.h>
*/
import "C"
import (
    "encoding/hex"
    "unsafe"
)

type BLSBytes struct{
   instance C.BytesWrapper
}

func NewBLSBytesFromBytes( buffer []byte )*BLSBytes{
    size := len(buffer)
    cBuffer := (*C.uint8_t)(C.CBytes(buffer))
    blsBytes := &BLSBytes{
        instance : C.BytesWrapperInit(cBuffer,C.size_t(size)),
    }
    C.free(unsafe.Pointer(cBuffer))
    return blsBytes
}

func (b *BLSBytes) Free(){
   C.BytesWrapperFree(b.instance)
}

func (b *BLSBytes) Size() int {
    return int(C.BytesWrapperSize(b.instance))
}

func (b *BLSBytes) Bytes() []byte {
  begin:=C.BytesWrapperBegin(b.instance)
  size :=C.BytesWrapperSize(b.instance)
  return C.GoBytes(unsafe.Pointer(begin), C.int(size))
}

func (b *BLSBytes) String()string{
    return  hex.EncodeToString(b.Bytes())
}

