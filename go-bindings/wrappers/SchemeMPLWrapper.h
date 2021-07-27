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

#include <stddef.h>
#include <stdint.h>

#include "BytesWrapper.h"
#include "GoWrapper.h"
#include "PrivateKeyWrapper.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef void* BasicSchemeMPLWrapper;

BasicSchemeMPLWrapper BasicSchemeMPLWrapperInit();

HandleRetWrapper BasicSchemeMPLWrapperKeyGen(
    BasicSchemeMPLWrapper basicScheme,
    const uint8_t* seed,
    size_t size);

BytesWrapper BasicSchemeMPLWrapperSkToPk();

HandleRetWrapper BasicSchemeMPLWrapperAggregateG1Element(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper* publicKeys,
    int num);

HandleRetWrapper BasicSchemeMPLWrapperAggregateG2Element(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper* signatures,
    int num);

IntRetWrapper BasicSchemeMPLWrapperAggregateVerify(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper* publicKeys,
    int keyNum,
    const BytesWrapper* messages,
    int msgNum,
    const BytesWrapper signature);

HandleRetWrapper BasicSchemeMPLDeriveChildSk(
    BasicSchemeMPLWrapper basicScheme,
    PrivateKeyWrapper master,
    uint32_t index);

HandleRetWrapper BasicSchemeMPLDeriveChildSkUnhardened(
    BasicSchemeMPLWrapper basicScheme,
    PrivateKeyWrapper master,
    uint32_t index);

HandleRetWrapper BasicSchemeMPLDeriveChildPkUnhardened(
    BasicSchemeMPLWrapper basicScheme,
    BytesWrapper master,
    uint32_t index);

HandleRetWrapper BasicSchemeMPLWrapperSign(
    BasicSchemeMPLWrapper basicScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t* message,
    size_t size);

IntRetWrapper BasicSchemeMPLWrapperVerify(
    BasicSchemeMPLWrapper basicScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t* message,
    size_t size,
    BytesWrapper signatureBytes);

typedef void* AugSchemeMPLWrapper;

AugSchemeMPLWrapper AugSchemeMPLWrapperInit();

HandleRetWrapper AugSchemeMPLWrapperKeyGen(
    AugSchemeMPLWrapper augScheme,
    const uint8_t* seed,
    size_t size);

BytesWrapper AugSchemeMPLWrapperSign(
    AugSchemeMPLWrapper augScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t* message,
    size_t size);

BytesWrapper AugSchemeMPLWrapperPrependingSign(
    AugSchemeMPLWrapper augScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t* message,
    size_t size,
    BytesWrapper publicKeyWrapper);

BytesWrapper AugSchemeMPLWrapperAggregateG1Element(
    AugSchemeMPLWrapper augScheme,
    const BytesWrapper* publicKeys,
    int num);

BytesWrapper AugSchemeMPLWrapperAggregateG2Element(
    AugSchemeMPLWrapper augScheme,
    const BytesWrapper* signatures,
    int num);

int AugSchemeMPLWrapperVerify(
    AugSchemeMPLWrapper augScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t* message,
    size_t size,
    BytesWrapper signatureBytes);

int AugSchemeMPLWrapperAggregateVerify(
    AugSchemeMPLWrapper augScheme,
    const BytesWrapper* publicKeys,
    int keyNum,
    const BytesWrapper* messages,
    int msgNum,
    const BytesWrapper signature);

HandleRetWrapper AugSchemeMPLDeriveChildSk(
    AugSchemeMPLWrapper augScheme,
    PrivateKeyWrapper master,
    uint32_t index);

PrivateKeyWrapper AugSchemeMPLDeriveChildSkUnhardened(
    AugSchemeMPLWrapper augScheme,
    PrivateKeyWrapper master,
    uint32_t index);

BytesWrapper AugSchemeMPLDeriveChildPkUnhardened(
    AugSchemeMPLWrapper augScheme,
    BytesWrapper master,
    uint32_t index);

typedef void* PopSchemeMPLWrapper;

PopSchemeMPLWrapper PopSchemeMPLWrapperInit();

PrivateKeyWrapper PopSchemeMPLWrapperKeyGen(
    PopSchemeMPLWrapper popScheme,
    const uint8_t* seed,
    size_t size);

BytesWrapper PopSchemeMPLWrapperSign(
    PopSchemeMPLWrapper popScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t* message,
    size_t size);

int PopSchemeMPLWrapperVerify(
    PopSchemeMPLWrapper popScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t* message,
    size_t size,
    BytesWrapper signatureBytes);

BytesWrapper PopSchemeMPLWrapperAggregateG1Element(
    PopSchemeMPLWrapper popScheme,
    const BytesWrapper* publicKeys,
    int num);

BytesWrapper PopSchemeMPLWrapperAggregateG2Element(
    PopSchemeMPLWrapper popScheme,
    const BytesWrapper* signatures,
    int num);

int PopSchemeMPLWrapperAggregateVerify(
    PopSchemeMPLWrapper popScheme,
    const BytesWrapper* publicKeys,
    int keyNum,
    const BytesWrapper* messages,
    int msgNum,
    const BytesWrapper signature);

PrivateKeyWrapper PopSchemeMPLDeriveChildSk(
    PopSchemeMPLWrapper popScheme,
    PrivateKeyWrapper master,
    uint32_t index);

PrivateKeyWrapper PopSchemeMPLDeriveChildSkUnhardened(
    PopSchemeMPLWrapper popScheme,
    PrivateKeyWrapper master,
    uint32_t index);

BytesWrapper PopSchemeMPLDeriveChildPkUnhardened(
    PopSchemeMPLWrapper popScheme,
    BytesWrapper master,
    uint32_t index);

BytesWrapper PopSchemeMPLPopProve(
    PopSchemeMPLWrapper popScheme,
    PrivateKeyWrapper privateKey);

#ifdef __cplusplus
}
#endif
#endif  // BLS_GO_BINDINGS_SCHEME_MPL_WRAPPER_H
