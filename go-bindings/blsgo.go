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
	"runtime"
	"unsafe"
)

const (
	G1ElementSize = 48
	G2ElementSize = 96
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
	instance C.PrivateKeyWrapper
}

func NewPrivateKeyFromBytes(bytes []byte) (*PrivateKey, error) {
	cBuffer, size := bytesToCUint8Bytes(bytes)
	defer C.free(unsafe.Pointer(cBuffer))
	privateKey := &PrivateKey{
		instance: C.PrivateKeyWrapperFromBytes(cBuffer, size),
	}
	return privateKey, nil
}

func (sk *PrivateKey) GetG2Power() (*G1Element, error) {
	return nil, nil
}

func (sk *PrivateKey) IsZero() bool {
	zero := C.PrivateKeyWrapperIsZero(sk.instance)
	return zero == 1
}

func (sk *PrivateKey) Bytes() []byte {
	b := C.PrivateKeyWrapperSerialize(sk.instance)
	buffer := newBytesBufferFromBytesWrapper(b)
	return buffer.Bytes()
}

func (sk *PrivateKey) Equals(other *PrivateKey) bool {
	return true
}

func (sk *PrivateKey) String() string {
	return hex.EncodeToString(sk.Bytes())
}

func (sk *PrivateKey) IsEqual(key *PrivateKey) bool {
	return bytes.Equal(sk.Bytes(), key.Bytes())
}

func (sk *PrivateKey) GetG1Element() (*G1Element, error) {
	g1p := C.PrivateKeyWrapperGetG1Element(sk.instance)
	data := newBytesBufferFromBytesWrapper(g1p)
	g1, err := newG1ElementFromBytesBuffer(data)
	if err != nil {
		return nil, err
	}
	return g1, nil
}

func PrivateKeyAggregate(privateKeys []*PrivateKey) (*PrivateKey,error) {
	num := len(privateKeys)
	privKeys := make([]C.PrivateKeyWrapper, num)
	for i, k := range privateKeys {
		privKeys[i] = (*k).instance
	}
	augKey := C.PrivateKeyWrapperAggregate((*C.PrivateKeyWrapper)(unsafe.Pointer(&privKeys[0])), C.int(num))
	privateKey := &PrivateKey{
		instance: augKey,
	}
	return privateKey,nil
}

//G1Element g1 element
type G1Element struct {
	instance *bytesBuffer        // c bytes buffer instance
	data     [G1ElementSize]byte // bytes data
	status   int8                //
}

func NewG1ElementFromBytes(buffer []byte) (*G1Element, error) {
	if len(buffer) != G1ElementSize {
		return nil, fmt.Errorf("Invalid G1Element data length ")
	}
	bytes := newBytesBufferFromBytes(buffer)
	g1 := &G1Element{
		instance: bytes,
	}
	copy(g1.data[:], buffer)
	return g1, nil
}

func newG1ElementFromBytesBuffer(data *bytesBuffer) (*G1Element, error) {
	if data == nil {
		return nil, fmt.Errorf("Invalid bytes buffer ")
	}
	g1 := &G1Element{
		instance: data,
	}
	copy(g1.data[:], data.Bytes())
	return g1, nil
}

func (g1 *G1Element) Bytes() []byte {
	return g1.data[:]
}

func (g1 *G1Element) IsEqual(element *G1Element) bool {
	return bytes.Equal(g1.Bytes(), element.Bytes())
}

func (g1 *G1Element) Add(element *G1Element) *G1Element {
	return nil
}

func (g1 *G1Element) Size() int {
	return G1ElementSize
}

func (g1 G1Element) GetFingerprint() (uint32,error) {
	fingerpint := C.G1ElementGetFingerprint(g1.instance.instance)
	return uint32(fingerpint),nil
}

func (g1 *G1Element) String() string {
	return hex.EncodeToString(g1.data[:])
}

type G2Element struct {
	//instance C.G2ElementWrapper
	instance *bytesBuffer
	data     [G2ElementSize]byte
	status   int8
}

func NewG2ElementFromBytes(buffer []byte) (*G2Element, error) {
	if len(buffer) != G2ElementSize {
		return nil, fmt.Errorf("Invalid G2Element data length ")
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
		return nil, fmt.Errorf("Invalid data ")
	}
	g2 := &G2Element{
		instance: data,
	}
	copy(g2.data[:], data.Bytes())
	return g2, nil
}

func (g2 *G2Element) Bytes() []byte {
	return g2.data[:]
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
	// Sign
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
		sigs[i] = k.instance.instance
	}
	augKey := C.BasicSchemeMPLWrapperAggregateG2Element(bs.instance, (*C.BytesWrapper)(unsafe.Pointer(&sigs[0])), C.int(num))
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG2ElementFromBytesBuffer(data)
}

func (bs *BasicSchemeMPL) AggregatePublicKeys(publicKeys []*G1Element) (*G1Element, error) {
	num := len(publicKeys)
	pubKeys := make([]C.BytesWrapper, num)
	for i, k := range publicKeys {
		pubKeys[i] = k.instance.instance
	}
	augKey := C.BasicSchemeMPLWrapperAggregateG1Element(bs.instance, (*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(num))
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
		pubKeys = append(pubKeys, key.instance.instance)
	}

	ok := C.BasicSchemeMPLWrapperAggregateVerify(bs.instance,
		(*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(keyNum),
		(*C.BytesWrapper)(unsafe.Pointer(&messageBytes[0])), C.int(msgNum),
		signature.instance.instance)
	if ok > 0 {
		return true, nil
	}
	return false, nil
}

func (bs *BasicSchemeMPL) DeriveChildSk(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	panic("implement me")
}

func (bs *BasicSchemeMPL) DeriveChildSkUnhardened(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	panic("implement me")
}

func (bs *BasicSchemeMPL) DeriveChildPkUnhardened(publicKey *G1Element, index uint32) (*G1Element, error) {
	panic("implement me")
}

func (bs *BasicSchemeMPL) Aggregate(publicKeys []*G1Element) (*G1Element, error) {
	num := len(publicKeys)
	pubKeys := make([]C.BytesWrapper, num)
	for i, k := range publicKeys {
		pubKeys[i] = k.instance.instance
	}
	augKey := C.BasicSchemeMPLWrapperAggregateG1Element(bs.instance, (*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(num))
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG1ElementFromBytesBuffer(data)
}
func (bs *BasicSchemeMPL) Sign(privateKey *PrivateKey, message []byte) (*G2Element, error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	sig := C.BasicSchemeMPLWrapperSign(bs.instance, privateKey.instance, cBuffer, size)
	data := newBytesBufferFromBytesWrapper(sig)
	return newG2ElementFromBytesBuffer(data)
}

func (bs *BasicSchemeMPL) Verify(publicKey *G1Element, message []byte, signature *G2Element) (bool, error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ok := C.BasicSchemeMPLWrapperVerify(bs.instance, publicKey.instance.instance, cBuffer, size, signature.instance.instance)
	return ok > 0, nil
}
func (bs *BasicSchemeMPL) KeyGen(seed []byte) (*PrivateKey, error) {
	cBuffer, size := bytesToCUint8Bytes(seed)
	defer C.free(unsafe.Pointer(cBuffer))
	if size < 32 {
		return nil, fmt.Errorf("seed size must >= 32")
	}
	var privateKeyWrapper C.PrivateKeyWrapper = C.BasicSchemeMPLWrapperKeyGen(bs.instance, cBuffer, C.size_t(size))
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
	if size < 32 {
		return nil, fmt.Errorf("seed size must >= 32")
	}
	var privateKeyWrapper C.PrivateKeyWrapper = C.AugSchemeMPLWrapperKeyGen(a.instance, cBuffer, C.size_t(size))
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
	sig := C.AugSchemeMPLWrapperSign(a.instance, privateKey.instance, cBuffer, size)
	data := newBytesBufferFromBytesWrapper(sig)
	return newG2ElementFromBytesBuffer(data)
}

func (a AugSchemeMPL) PrependingSign(privateKey *PrivateKey, message []byte,publicKey *G1Element)(signature *G2Element, err error){
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	sig := C.AugSchemeMPLWrapperPrependingSign(a.instance, privateKey.instance, cBuffer, size,publicKey.instance.instance)
	data := newBytesBufferFromBytesWrapper(sig)
	return newG2ElementFromBytesBuffer(data)
}

func (a AugSchemeMPL) Verify(publicKey *G1Element, message []byte, signature *G2Element) (bool, error) {
	cBuffer, size := bytesToCUint8Bytes(message)
	defer C.free(unsafe.Pointer(cBuffer))
	ok := C.AugSchemeMPLWrapperVerify(a.instance, publicKey.instance.instance, cBuffer, size, signature.instance.instance)
	return ok > 0, nil
}

func (a AugSchemeMPL) AggregateSignatures(signatures []*G2Element) (*G2Element, error) {
	num := len(signatures)
	signs := make([]C.BytesWrapper, num)
	for i, k := range signatures {
		signs[i] = k.instance.instance
	}
	augKey := C.AugSchemeMPLWrapperAggregateG2Element(a.instance, (*C.BytesWrapper)(unsafe.Pointer(&signs[0])), C.int(num))
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG2ElementFromBytesBuffer(data)
}

func (a AugSchemeMPL) AggregatePublicKeys(publicKeys []*G1Element) (*G1Element, error) {
	num := len(publicKeys)
	pubKeys := make([]C.BytesWrapper, num)
	for i, k := range publicKeys {
		pubKeys[i] = k.instance.instance
	}
	augKey := C.AugSchemeMPLWrapperAggregateG1Element(a.instance, (*C.BytesWrapper)(unsafe.Pointer(&pubKeys[0])), C.int(num))
	data := newBytesBufferFromBytesWrapper(augKey)
	return newG1ElementFromBytesBuffer(data)
}

func (a AugSchemeMPL) AggregateVerify(publicKeys []*G1Element, messages [][]byte, signature *G2Element) (bool, error) {
	panic("implement me")
}

func (a AugSchemeMPL) DeriveChildSk(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	sk := C.AugSchemeMPLDeriveChildSk(a.instance, privateKey.instance, C.uint(index))
	return &PrivateKey{
		instance: sk,
	}, nil
}

func (a AugSchemeMPL) DeriveChildSkUnhardened(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	panic("implement me")
}

func (a AugSchemeMPL) DeriveChildPkUnhardened(publicKey *G1Element, index uint32) (*G1Element, error) {
	panic("implement me")
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
	if size < 32 {
		return nil, fmt.Errorf("seed size must >= 32")
	}
	var privateKeyWrapper C.PrivateKeyWrapper = C.PopSchemeMPLWrapperKeyGen(p.instance, cBuffer, C.size_t(size))
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
	panic("implement me")
}

func (p PopSchemeMPL) Verify(publicKey *G1Element, message []byte, signature *G2Element) (bool, error) {
	panic("implement me")
}

func (p PopSchemeMPL) AggregateSignatures(signatures []*G2Element) (*G2Element, error) {
	panic("implement me")
}

func (p PopSchemeMPL) AggregatePublicKeys(publicKeys []*G1Element) (*G1Element, error) {
	panic("implement me")
}

func (p PopSchemeMPL) AggregateVerify(publicKeys []*G1Element, messages [][]byte, signature *G2Element) (bool, error) {
	panic("implement me")
}

func (p PopSchemeMPL) DeriveChildSk(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	panic("implement me")
}

func (p PopSchemeMPL) DeriveChildSkUnhardened(privateKey *PrivateKey, index uint32) (*PrivateKey, error) {
	panic("implement me")
}

func (p PopSchemeMPL) DeriveChildPkUnhardened(publicKey *G1Element, index uint32) (*G1Element, error) {
	panic("implement me")
}

type HKDF256HASH [32]byte

//HKDF256 Implements HKDF as specified in RFC5869:
// https://tools.ietf.org/html/rfc5869,
// with sha256 as the hash function.
type HKDF256 struct {
}

func HKDF256Extract(salt []byte, ikm []byte) *HKDF256HASH {
	return nil
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
