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
#cgo LDFLAGS: -lrelic_s -lstdc++ -lblsgo -lbls
#include "gobindings.h"
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

const (
	// PrivateKeySize the length of bls private key bytes
	PrivateKeySize = 32
	// G1ElementSize the length of bls public key bytes
	G1ElementSize = 48
	// G2ElementSize the length of bls signature bytes
	G2ElementSize = 96
	// Hash256Size hash 256 size
	Hash256Size = 32
	// SeedMinSize the minimum length of seed
	SeedMinSize = 32
)

var (
	ErrInvalidPrivateKeyLength = errors.New("Invalid private key length ")
	ErrInvalidG1ElementLength  = errors.New("Invalid G1Element data length ")
	ErrInvalidBufferLength     = errors.New("Invalid buffer data length ")
	ErrInvalidG2ElementLength  = errors.New("Invalid G2Element data length ")
	ErrInvalidSeedLength       = errors.New("Invalid Seed length ")
)

// utils
// bytesToCUint8Bytes go bytes to c uint8_t * buffer
func bytesToCUint8Bytes(buffer []byte) (*C.uint8_t, C.size_t) {
	size := len(buffer)
	cBuffer := (*C.uint8_t)(C.CBytes(buffer))
	return cBuffer, C.size_t(size)
}

// bytesBuffer internal bls bytes wrapper
type bytesBuffer struct {
	instance C.BytesWrapper
}

// free bytes buffer c buffer
func freeBytesBuffer(b *bytesBuffer) {
	C.BytesWrapperFree(b.instance)
}

func newBytesBufferFromBytesWrapper(byteWrapper C.BytesWrapper) *bytesBuffer {
	blsBytes := &bytesBuffer{
		instance: byteWrapper,
	}
	runtime.SetFinalizer(blsBytes, freeBytesBuffer)
	return blsBytes
}

func newBytesBufferFromBytes(buffer []byte) *bytesBuffer {
	cBuffer, size := bytesToCUint8Bytes(buffer)
	defer C.free(unsafe.Pointer(cBuffer))
	blsBytes := &bytesBuffer{
		instance: C.BytesWrapperInit(cBuffer, size),
	}
	runtime.SetFinalizer(blsBytes, freeBytesBuffer)
	return blsBytes
}

func (b *bytesBuffer) cWrapper() C.BytesWrapper {
	return b.instance
}

func (b *bytesBuffer) Size() int {
	return int(C.BytesWrapperSize(b.instance))
}

func (b *bytesBuffer) Bytes() []byte {
	begin := C.BytesWrapperBegin(b.instance)
	size := C.BytesWrapperSize(b.instance)
	return C.GoBytes(unsafe.Pointer(begin), C.int(size))
}

func (b *bytesBuffer) Index(index int) (byte, error) {
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

func (b *bytesBuffer) String() string {
	return hex.EncodeToString(b.Bytes())
}

// PrivateKey private key secret key
type PrivateKey struct {
	instance    C.PrivateKeyWrapper
	data        [PrivateKeySize]byte
	isZeroValue bool
}

func NewPrivateKeyFromBytes(bytes []byte) (*PrivateKey, error) {
	if len(bytes) != PrivateKeySize {
		return nil, ErrInvalidPrivateKeyLength
	}
	cBuffer, size := bytesToCUint8Bytes(bytes)
	defer C.free(unsafe.Pointer(cBuffer))
	ret := C.PrivateKeyWrapperFromBytes(cBuffer, size)
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	instance := (C.PrivateKeyWrapper)(ret.handle)
	zero, err := privateKeyIsZero(instance)
	if err != nil {
		return nil, err
	}
	var data [PrivateKeySize]byte
	copy(data[:], bytes)
	privateKey := &PrivateKey{
		instance:    instance,
		isZeroValue: zero,
		data:        data,
	}
	return privateKey, nil
}

func (sk *PrivateKey) GetG2Power(g2 *G2Element) (*G2Element, error) {
	ret := C.PrivateKeyWrapperGetG2Power(sk.instance, g2.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	bs := newBytesBufferFromBytesWrapper((C.BytesWrapper)(ret.handle))
	return newG2ElementFromBytesBuffer(bs)
}

func privateKeyIsZero(instance C.PrivateKeyWrapper) (bool, error) {
	ret := C.PrivateKeyWrapperIsZero(instance)
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return false, fmt.Errorf(C.GoString(ret.err))
	}
	return ret.ret == 1, nil
}

func (sk *PrivateKey) IsZero() bool {
	return sk.isZeroValue
}

func (sk *PrivateKey) cWrapper() C.PrivateKeyWrapper {
	return sk.instance
}

func (sk *PrivateKey) Bytes() []byte {
	//b := C.PrivateKeyWrapperSerialize(sk.instance)
	//buffer := newBytesBufferFromBytesWrapper(b)
	//copy(sk.data,buffer.Bytes())
	return sk.data[:]
}

func (sk *PrivateKey) Equals(other *PrivateKey) (bool, error) {
	if other == nil {
		return false, nil
	}
	if bytes.Equal(sk.Bytes(), other.Bytes()) {
		return true, nil
	}
	ret := C.PrivateKeyWrapperEquals(sk.instance, other.instance)
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return false, fmt.Errorf(C.GoString(ret.err))
	}
	if ret.ret > 0 {
		return true, nil
	}
	return false, nil
}

func (sk PrivateKey) MulG1Element(g1 *G1Element) (*G1Element, error) {
	ret := C.PrivateKeyWrapperMulG1Element(sk.instance, g1.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	bs := newBytesBufferFromBytesWrapper((C.BytesWrapper)(ret.handle))
	return newG1ElementFromBytesBuffer(bs)
}

func (sk PrivateKey) MulG2Element(g2 *G2Element) (*G2Element, error) {
	ret := C.PrivateKeyWrapperMulG2Element(sk.instance, g2.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	bs := newBytesBufferFromBytesWrapper((C.BytesWrapper)(ret.handle))
	return newG2ElementFromBytesBuffer(bs)
}

func (sk *PrivateKey) String() string {
	return hex.EncodeToString(sk.Bytes())
}

func (sk *PrivateKey) IsEqual(key *PrivateKey) (bool, error) {
	return sk.Equals(key)
}

func (sk *PrivateKey) GetG1Element() (*G1Element, error) {
	ret := C.PrivateKeyWrapperGetG1Element(sk.instance)
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	data := newBytesBufferFromBytesWrapper((C.BytesWrapper)(ret.handle))
	g1, err := newG1ElementFromBytesBuffer(data)
	if err != nil {
		return nil, err
	}
	return g1, nil
}

func PrivateKeyAggregate(privateKeys []*PrivateKey) (*PrivateKey, error) {
	num := len(privateKeys)
	privKeys := make([]C.PrivateKeyWrapper, num)
	for i, k := range privateKeys {
		privKeys[i] = (*k).instance
	}
	ret := C.PrivateKeyWrapperAggregate((*C.PrivateKeyWrapper)(unsafe.Pointer(&privKeys[0])), C.int(num))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	privateKey := &PrivateKey{
		instance: (C.PrivateKeyWrapper)(ret.handle),
	}
	return privateKey, nil
}

//G1Element g1 element
type G1Element [G1ElementSize]byte

func G1ElementGenerator() (*G1Element, error) {
	ret := C.G1ElementGenerator()
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	bs := newBytesBufferFromBytesWrapper((C.BytesWrapper)(ret.handle))
	var g1 G1Element
	copy(g1[:], bs.Bytes())
	return &g1, nil
}

func NewG1ElementFromBytes(buffer []byte) (*G1Element, error) {
	if len(buffer) != G1ElementSize {
		return nil, ErrInvalidG1ElementLength
	}
	var g1 G1Element
	copy(g1[:], buffer)
	return &g1, nil
}

func newG1ElementFromBytesBuffer(data *bytesBuffer) (*G1Element, error) {
	if data == nil {
		return nil, ErrInvalidBufferLength
	}
	var g1 G1Element
	copy(g1[:], data.Bytes())
	return &g1, nil
}

func (g1 *G1Element) Bytes() []byte {
	return g1[:]
}

func (g1 *G1Element) IsEqual(element *G1Element) bool {
	return bytes.Equal(g1.Bytes(), element.Bytes())
}

func (g1 *G1Element) Add(addend *G1Element) (*G1Element, error) {
	ret := C.G1ElementAdd(g1.cWrapper(), addend.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	wrapper := newBytesBufferFromBytesWrapper((C.BytesWrapper)(ret.handle))
	return newG1ElementFromBytesBuffer(wrapper)
}

func (g1 *G1Element) Size() int {
	return G1ElementSize
}

func (g1 *G1Element) cWrapper() C.BytesWrapper {
	return newBytesBufferFromBytes(g1[:]).cWrapper()
}

func (g1 G1Element) GetFingerprint() (uint32, error) {
	ret := C.G1ElementGetFingerprint(g1.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return 0, fmt.Errorf(C.GoString(ret.err))
	}
	return uint32(ret.ret), nil
}

func (g1 *G1Element) String() string {
	return hex.EncodeToString(g1[:])
}

type G2Element [G2ElementSize]byte

func NewG2ElementFromBytes(buffer []byte) (*G2Element, error) {
	if len(buffer) != G2ElementSize {
		return nil, ErrInvalidG2ElementLength
	}
	bytes := newBytesBufferFromBytes(buffer)
	g2, err := newG2ElementFromBytesBuffer(bytes)
	if err != nil {
		return nil, err
	}
	return g2, nil
}

func newG2ElementFromBytesBuffer(data *bytesBuffer) (*G2Element, error) {
	if data == nil {
		return nil, ErrInvalidBufferLength
	}
	var g2 G2Element
	copy(g2[:], data.Bytes())
	return &g2, nil
}

func (g2 *G2Element) Bytes() []byte {
	return g2[:]
}

func (g2 *G2Element) cWrapper() C.BytesWrapper {
	return newBytesBufferFromBytes(g2[:]).cWrapper()
}

func (g2 *G2Element) Size() int {
	return G2ElementSize
}

func (g2 *G2Element) IsEqual(element *G2Element) bool {
	return bytes.Equal(g2.Bytes(), element.Bytes())
}

func (g2 *G2Element) String() string {
	return hex.EncodeToString(g2.Bytes())
}

type SchemeMPL interface {
	KeyGen(seed []byte) (*PrivateKey, error)
	//SkToPk Generates a public key from a secret key
	SkToPk(privateKey *PrivateKey) ([]byte, error)
	//SkToG1 private key to public key
	SkToG1(privateKey *PrivateKey) (*G1Element, error)
	// Sign signature
	Sign(privateKey *PrivateKey, message []byte) (signature *G2Element, err error)
	Verify(publicKey *G1Element, message []byte, signature *G2Element) (bool, error)
	AggregateSignatures(signatures []*G2Element) (*G2Element, error)
	AggregatePublicKeys(publicKeys []*G1Element) (*G1Element, error)
	AggregateVerify(publicKeys []*G1Element, messages [][]byte, signature *G2Element) (bool, error)
	DeriveChildSk(privateKey *PrivateKey, index uint32) (*PrivateKey, error)
	DeriveChildSkUnhardened(privateKey *PrivateKey, index uint32) (*PrivateKey, error)
	DeriveChildPkUnhardened(publicKey *G1Element, index uint32) (*G1Element, error)
}

var _ SchemeMPL = (*BasicSchemeMPL)(nil)

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

func (bs *BasicSchemeMPL) SkToPk(privateKey *PrivateKey) ([]byte, error) {
	g1, err := bs.SkToG1(privateKey)
	if err != nil {
		return nil, err
	}
	return g1.Bytes(), nil
}

func (bs *BasicSchemeMPL) SkToG1(privateKey *PrivateKey) (*G1Element, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("Invalid privateKey ")
	}
	publicKey, err := privateKey.GetG1Element()
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}
func (bs *BasicSchemeMPL) AggregateSignatures(signatures []*G2Element) (*G2Element, error) {
	num := len(signatures)
	sigs := make([]C.BytesWrapper, num)
	for i, k := range signatures {
		sigs[i] = k.cWrapper()
	}
	ret := C.BasicSchemeMPLWrapperAggregateG2Element(bs.instance, (*C.BytesWrapper)(unsafe.Pointer(&sigs[0])), C.int(num))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	augKey := (C.BytesWrapper)(ret.handle)
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG2ElementFromBytesBuffer(data)
}

func (bs *BasicSchemeMPL) AggregatePublicKeys(publicKeys []*G1Element) (*G1Element, error) {
	num := len(publicKeys)
	pubKeys := make([]C.BytesWrapper, num)
	for i, k := range publicKeys {
		pubKeys[i] = k.cWrapper()
	}
	ret := C.BasicSchemeMPLWrapperAggregateG1Element(bs.instance, (*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(num))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	augKey := (C.BytesWrapper)(ret.handle)
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG1ElementFromBytesBuffer(data)
}

func (bs *BasicSchemeMPL) AggregateVerify(publicKeys []*G1Element, messages [][]byte, signature *G2Element) (bool, error) {
	keyNum := len(publicKeys)
	msgNum := len(messages)
	if keyNum != msgNum {
		return false, fmt.Errorf("Invalid parameter ")
	}
	messageBytes := make([]C.BytesWrapper, 0)
	for _, message := range messages {
		fromBytes := newBytesBufferFromBytes(message)
		messageBytes = append(messageBytes, fromBytes.instance)
	}
	pubKeys := make([]C.BytesWrapper, 0)
	for _, key := range publicKeys {
		pubKeys = append(pubKeys, key.cWrapper())
	}

	ret := C.BasicSchemeMPLWrapperAggregateVerify(bs.instance,
		(*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(keyNum),
		(*C.BytesWrapper)(unsafe.Pointer(&messageBytes[0])), C.int(msgNum),
		signature.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return false, fmt.Errorf(C.GoString(ret.err))
	}
	if ret.ret > 0 {
		return true, nil
	}
	return false, nil
}

func (bs *BasicSchemeMPL) DeriveChildSk(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	ret := C.BasicSchemeMPLDeriveChildSk(bs.instance, privateKey.instance, C.uint32_t(index))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	sk := (C.PrivateKeyWrapper)(ret.handle)
	return &PrivateKey{
		instance: sk,
	}, nil
}

func (bs *BasicSchemeMPL) DeriveChildSkUnhardened(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	ret := C.BasicSchemeMPLDeriveChildSkUnhardened(bs.instance, privateKey.instance, C.uint32_t(index))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	sk := (C.PrivateKeyWrapper)(ret.handle)
	return &PrivateKey{
		instance: sk,
	}, nil
}

func (bs *BasicSchemeMPL) DeriveChildPkUnhardened(publicKey *G1Element, index uint32) (*G1Element, error) {
	ret := C.BasicSchemeMPLDeriveChildPkUnhardened(bs.instance, publicKey.cWrapper(), C.uint32_t(index))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	pubKey := (C.BytesWrapper)(ret.handle)
	wrapper := newBytesBufferFromBytesWrapper(pubKey)
	return newG1ElementFromBytesBuffer(wrapper)
}

func (bs *BasicSchemeMPL) Aggregate(publicKeys []*G1Element) (*G1Element, error) {
	num := len(publicKeys)
	pubKeys := make([]C.BytesWrapper, num)
	for i, k := range publicKeys {
		pubKeys[i] = k.cWrapper()
	}
	ret := C.BasicSchemeMPLWrapperAggregateG1Element(bs.instance, (*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(num))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	augKey := (C.BytesWrapper)(ret.handle)
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG1ElementFromBytesBuffer(data)
}

func (bs *BasicSchemeMPL) Sign(privateKey *PrivateKey, message []byte) (*G2Element, error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ret := C.BasicSchemeMPLWrapperSign(bs.instance, privateKey.instance, cBuffer, size)
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	sig := (C.BytesWrapper)(ret.handle)
	data := newBytesBufferFromBytesWrapper(sig)
	return newG2ElementFromBytesBuffer(data)
}

func (bs *BasicSchemeMPL) Verify(publicKey *G1Element, message []byte, signature *G2Element) (bool, error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ret := C.BasicSchemeMPLWrapperVerify(bs.instance, publicKey.cWrapper(), cBuffer, size, signature.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return false, fmt.Errorf(C.GoString(ret.err))
	}
	return ret.ret > 0, nil
}
func (bs *BasicSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	cBuffer, size := bytesToCUint8Bytes(seed)
	defer C.free(unsafe.Pointer(cBuffer))
	if size < SeedMinSize {
		return nil, ErrInvalidSeedLength
	}

	ret := C.BasicSchemeMPLWrapperKeyGen(bs.instance, cBuffer, C.size_t(size))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	var privateKeyWrapper = (C.PrivateKeyWrapper)(ret.handle)
	privateKey := &PrivateKey{
		instance: privateKeyWrapper,
	}
	return privateKey, nil
}

var _ SchemeMPL = (*AugSchemeMPL)(nil)

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
func (a AugSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	cBuffer, size := bytesToCUint8Bytes(seed)
	defer C.free(unsafe.Pointer(cBuffer))
	if size < SeedMinSize {
		return nil, ErrInvalidSeedLength
	}
	ret := C.AugSchemeMPLWrapperKeyGen(a.instance, cBuffer, C.size_t(size))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	var privateKeyWrapper = (C.PrivateKeyWrapper)(ret.handle)
	 privateKey := &PrivateKey{
		instance: privateKeyWrapper,
	}
	return privateKey, nil
}

func (a AugSchemeMPL) SkToPk(privateKey *PrivateKey) ([]byte, error) {
	g1, err := a.SkToG1(privateKey)
	if err != nil {
		return nil, err
	}
	return g1.Bytes(), nil
}

func (a AugSchemeMPL) SkToG1(privateKey *PrivateKey) (*G1Element, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("Invalid privateKey ")
	}
	publicKey, err := privateKey.GetG1Element()
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func (a AugSchemeMPL) Sign(privateKey *PrivateKey, message []byte) (signature *G2Element, err error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ret := C.AugSchemeMPLWrapperSign(a.instance, privateKey.instance, cBuffer, size)
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	sig := (C.BytesWrapper)(ret.handle)
	data := newBytesBufferFromBytesWrapper(sig)
	return newG2ElementFromBytesBuffer(data)
}

func (a AugSchemeMPL) PrependingSign(privateKey *PrivateKey, message []byte, publicKey *G1Element) (signature *G2Element, err error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ret := C.AugSchemeMPLWrapperPrependingSign(a.instance, privateKey.instance, cBuffer, size, publicKey.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	sig := (C.BytesWrapper)(ret.handle)
	data := newBytesBufferFromBytesWrapper(sig)
	return newG2ElementFromBytesBuffer(data)
}

func (a AugSchemeMPL) Verify(publicKey *G1Element, message []byte, signature *G2Element) (bool, error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ret := C.AugSchemeMPLWrapperVerify(a.instance, publicKey.cWrapper(), cBuffer, size, signature.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return false, fmt.Errorf(C.GoString(ret.err))
	}
	return ret.ret > 0, nil
}

func (a AugSchemeMPL) AggregateSignatures(signatures []*G2Element) (*G2Element, error) {
	num := len(signatures)
	signs := make([]C.BytesWrapper, num)
	for i, k := range signatures {
		signs[i] = k.cWrapper()
	}
	ret := C.AugSchemeMPLWrapperAggregateG2Element(a.instance, (*C.BytesWrapper)(unsafe.Pointer(&signs[0])), C.int(num))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	augKey := (C.BytesWrapper)(ret.handle)
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG2ElementFromBytesBuffer(data)
}

func (a AugSchemeMPL) AggregatePublicKeys(publicKeys []*G1Element) (*G1Element, error) {
	num := len(publicKeys)
	pubKeys := make([]C.BytesWrapper, num)
	for i, k := range publicKeys {
		pubKeys[i] = k.cWrapper()
	}
	ret := C.AugSchemeMPLWrapperAggregateG1Element(a.instance, (*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(num))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	augKey := (C.BytesWrapper)(ret.handle)
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG1ElementFromBytesBuffer(data)
}

func (a AugSchemeMPL) AggregateVerify(publicKeys []*G1Element, messages [][]byte, signature *G2Element) (bool, error) {
	keyNum := len(publicKeys)
	msgNum := len(messages)
	if keyNum != msgNum {
		return false, fmt.Errorf("Invalid parameter ")
	}
	messageBytes := make([]C.BytesWrapper, 0)
	for _, message := range messages {
		fromBytes := newBytesBufferFromBytes(message)
		messageBytes = append(messageBytes, fromBytes.instance)
	}
	pubKeys := make([]C.BytesWrapper, 0)
	for _, key := range publicKeys {
		pubKeys = append(pubKeys, key.cWrapper())
	}

	ret := C.AugSchemeMPLWrapperAggregateVerify(a.instance,
		(*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(keyNum),
		(*C.BytesWrapper)(unsafe.Pointer(&messageBytes[0])), C.int(msgNum),
		signature.cWrapper())
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return false, fmt.Errorf(C.GoString(ret.err))
	}
	if ret.ret > 0 {
		return true, nil
	}
	return false, nil
}

func (a AugSchemeMPL) DeriveChildSk(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	ret := C.AugSchemeMPLDeriveChildSk(a.instance, privateKey.instance, C.uint(index))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	return &PrivateKey{
		instance: (C.PrivateKeyWrapper)(ret.handle),
	}, nil
}

func (a AugSchemeMPL) DeriveChildSkUnhardened(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	ret := C.AugSchemeMPLDeriveChildSkUnhardened(a.instance, privateKey.instance, C.uint32_t(index))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	sk := (C.PrivateKeyWrapper)(ret.handle)
	return &PrivateKey{
		instance: sk,
	}, nil
}

func (a AugSchemeMPL) DeriveChildPkUnhardened(publicKey *G1Element, index uint32) (*G1Element, error) {
	ret := C.AugSchemeMPLDeriveChildPkUnhardened(a.instance, publicKey.cWrapper(), C.uint32_t(index))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	wrapper := newBytesBufferFromBytesWrapper((C.BytesWrapper)(ret.handle))
	return newG1ElementFromBytesBuffer(wrapper)
}

var _ SchemeMPL = (*PopSchemeMPL)(nil)

type PopSchemeMPL struct {
	instance C.PopSchemeMPLWrapper
}

func NewPopSchemeMPL() *PopSchemeMPL {
	popSchemeWrapper := C.PopSchemeMPLWrapperInit()
	augScheme := &PopSchemeMPL{
		instance: popSchemeWrapper,
	}
	return augScheme
}

func (p PopSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	cBuffer, size := bytesToCUint8Bytes(seed)
	defer C.free(unsafe.Pointer(cBuffer))
	if size < SeedMinSize {
		return nil, ErrInvalidSeedLength
	}
	ret := C.PopSchemeMPLWrapperKeyGen(p.instance, cBuffer, C.size_t(size))
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		return nil, fmt.Errorf(C.GoString(ret.err))
	}
	privateKeyWrapper := (C.PrivateKeyWrapper)(ret.handle)
	privateKey := &PrivateKey{
		instance: privateKeyWrapper,
	}
	return privateKey, nil
}

func (p PopSchemeMPL) SkToPk(privateKey *PrivateKey) ([]byte, error) {
	g1, err := p.SkToG1(privateKey)
	if err != nil {
		return nil, err
	}
	return g1.Bytes(), nil
}

func (p PopSchemeMPL) SkToG1(privateKey *PrivateKey) (*G1Element, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("Invalid privateKey ")
	}
	publicKey, err := privateKey.GetG1Element()
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func (p PopSchemeMPL) Sign(privateKey *PrivateKey, message []byte) (signature *G2Element, err error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	sig := C.PopSchemeMPLWrapperSign(p.instance, privateKey.instance, cBuffer, size)
	data := newBytesBufferFromBytesWrapper(sig)
	return newG2ElementFromBytesBuffer(data)
}

func (p PopSchemeMPL) Verify(publicKey *G1Element, message []byte, signature *G2Element) (bool, error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ok := C.PopSchemeMPLWrapperVerify(p.instance, publicKey.cWrapper(), cBuffer, size, signature.cWrapper())
	return ok > 0, nil
}

func (p PopSchemeMPL) AggregateSignatures(signatures []*G2Element) (*G2Element, error) {
	num := len(signatures)
	signs := make([]C.BytesWrapper, num)
	for i, k := range signatures {
		signs[i] = k.cWrapper()
	}
	augKey := C.PopSchemeMPLWrapperAggregateG2Element(p.instance, (*C.BytesWrapper)(unsafe.Pointer(&signs[0])), C.int(num))
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG2ElementFromBytesBuffer(data)
}

func (p PopSchemeMPL) AggregatePublicKeys(publicKeys []*G1Element) (*G1Element, error) {
	num := len(publicKeys)
	pubKeys := make([]C.BytesWrapper, num)
	for i, k := range publicKeys {
		pubKeys[i] = k.cWrapper()
	}
	augKey := C.PopSchemeMPLWrapperAggregateG1Element(p.instance, (*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(num))
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG1ElementFromBytesBuffer(data)
}

func (p PopSchemeMPL) AggregateVerify(publicKeys []*G1Element, messages [][]byte, signature *G2Element) (bool, error) {
	keyNum := len(publicKeys)
	msgNum := len(messages)
	if keyNum != msgNum {
		return false, fmt.Errorf("Invalid parameter ")
	}
	messageBytes := make([]C.BytesWrapper, 0)
	for _, message := range messages {
		fromBytes := newBytesBufferFromBytes(message)
		messageBytes = append(messageBytes, fromBytes.instance)
	}
	pubKeys := make([]C.BytesWrapper, 0)
	for _, key := range publicKeys {
		pubKeys = append(pubKeys, key.cWrapper())
	}

	ok := C.PopSchemeMPLWrapperAggregateVerify(p.instance,
		(*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(keyNum),
		(*C.BytesWrapper)(unsafe.Pointer(&messageBytes[0])), C.int(msgNum),
		signature.cWrapper())
	if ok > 0 {
		return true, nil
	}
	return false, nil
}

func (p PopSchemeMPL) DeriveChildSk(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	sk := C.PopSchemeMPLDeriveChildSk(p.instance, privateKey.instance, C.uint(index))
	return &PrivateKey{
		instance: sk,
	}, nil
}

func (p PopSchemeMPL) DeriveChildSkUnhardened(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	sk := C.PopSchemeMPLDeriveChildSkUnhardened(p.instance, privateKey.instance, C.uint32_t(index))
	return &PrivateKey{
		instance: sk,
	}, nil
}

func (p PopSchemeMPL) DeriveChildPkUnhardened(publicKey *G1Element, index uint32) (*G1Element, error) {
	b := C.PopSchemeMPLDeriveChildPkUnhardened(p.instance, publicKey.cWrapper(), C.uint32_t(index))
	wrapper := newBytesBufferFromBytesWrapper(b)
	return newG1ElementFromBytesBuffer(wrapper)
}

func (p PopSchemeMPL) PopProve(privateKey *PrivateKey) (*G2Element, error) {
	b := C.PopSchemeMPLPopProve(p.instance, privateKey.instance)
	wrapper := newBytesBufferFromBytesWrapper(b)
	return newG2ElementFromBytesBuffer(wrapper)
}

type HKDF256HASH [32]byte

//HKDF256 Implements HKDF as specified in RFC5869:
// https://tools.ietf.org/html/rfc5869,
// with sha256 as the hash function.
type HKDF256 struct {
}

func HKDF256Extract(salt []byte, ikm []byte) (*HKDF256HASH, error) {
	saltBytes := newBytesBufferFromBytes(salt)
	ikmBytes := newBytesBufferFromBytes(ikm)
	h := C.HKDF256Extract(saltBytes.instance, ikmBytes.instance)
	wrapper := newBytesBufferFromBytesWrapper(h)
	var outHash HKDF256HASH
	copy(outHash[:], wrapper.Bytes())
	return &outHash, nil
}

func HKDF256Expand(prk []byte, info []byte) []byte {
	return nil
}

func HKDF256ExtractExtractExpand(key []byte, salt []byte, info []byte) []byte {
	return nil
}

// HDKeys Implements HD keys as specified in EIP2333.
type HDKeys struct {
}

func NewPrivateKeyByHDKeysKeyGen(seed []byte) *PrivateKey {
	return nil
}

// IKMToLamportSk lamport sk
func IKMToLamportSk(ikm []byte, salt []byte) []byte {
	return nil
}

func ParentSkToLamportPK(parentSk *PrivateKey, index uint32) []byte {
	return nil
}

func Hash256(message []byte) ([Hash256Size]byte, error) {
	var sha [Hash256Size]byte
	cBuffer, size := bytesToCUint8Bytes(message)
	ret := C.Hash256(cBuffer, size)
	if ret.err != nil {
		defer C.free(unsafe.Pointer(ret.err))
		err := C.GoString(ret.err)
		return sha, fmt.Errorf(err)
	}
	wrapper := newBytesBufferFromBytesWrapper((C.BytesWrapper)(ret.handle))

	copy(sha[:], wrapper.Bytes())
	return sha, nil
}
