// Copyright 2020 Chia Network Inc
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#ifndef BLS_GO_BINDINGS_SCHEME_MPL_WRAPPER_H
#define BLS_GO_BINDINGS_SCHEME_MPL_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include "PrivateKeyWrapper.h"
#include "BytesWrapper.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef void * BasicSchemeMPLWrapper;

BasicSchemeMPLWrapper BasicSchemeMPLWrapperInit();

PrivateKeyWrapper BasicSchemeMPLWrapperKeyGen(BasicSchemeMPLWrapper basicScheme,const uint8_t * seed,size_t size);

BytesWrapper BasicSchemeMPLWrapperSkToPk();

BytesWrapper BasicSchemeMPLWrapperAggregateG1Element(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper * publicKeys,int num);

BytesWrapper BasicSchemeMPLWrapperAggregateG2Element(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper * signatures,int num);

int BasicSchemeMPLWrapperAggregateVerify(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper * publicKeys,int keyNum,
    const BytesWrapper * messages,int msgNum,
    const BytesWrapper signature);

BytesWrapper BasicSchemeMPLWrapperSign(
    BasicSchemeMPLWrapper basicScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t * message,size_t size);

int BasicSchemeMPLWrapperVerify(
    BasicSchemeMPLWrapper basicScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t * message,size_t size,
    BytesWrapper signatureBytes);

typedef void * AugSchemeMPLWrapper;

AugSchemeMPLWrapper AugSchemeMPLWrapperInit();

PrivateKeyWrapper AugSchemeMPLWrapperKeyGen(
    AugSchemeMPLWrapper augScheme,
    const uint8_t * seed,size_t size);

BytesWrapper AugSchemeMPLWrapperSign(
    AugSchemeMPLWrapper augScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t * message,size_t size);

int AugSchemeMPLWrapperVerify(
    AugSchemeMPLWrapper augScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t * message,size_t size,
    BytesWrapper signatureBytes);

int AugSchemeMPLWrapperAggregateVerify(
    AugSchemeMPLWrapper augScheme,
    const BytesWrapper * publicKeys,int keyNum,
    const BytesWrapper * messages,int msgNum,
    const BytesWrapper signature);

PrivateKeyWrapper AugSchemeMPLDeriveChildSk(AugSchemeMPLWrapper augScheme,PrivateKeyWrapper master,uint32_t index);

typedef void * PopSchemeMPLWrapper;

PopSchemeMPLWrapper PopSchemeMPLWrapperInit();

PrivateKeyWrapper PopSchemeMPLWrapperKeyGen(PopSchemeMPLWrapper popScheme,const uint8_t * seed,size_t size);

#ifdef __cplusplus
}
#endif
#endif  // BLS_GO_BINDINGS_SCHEME_MPL_WRAPPER_H
