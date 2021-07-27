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

#ifndef BLS_GO_BINDINGS_PRIVATE_KEY_WRAPPER_H
#define BLS_GO_BINDINGS_PRIVATE_KEY_WRAPPER_H
#include <stddef.h>
#include <stdint.h>

#include "BytesWrapper.h"
#include "GoWrapper.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef void *PrivateKeyWrapper;

HandleRetWrapper PrivateKeyWrapperFromBytes(const uint8_t *buffer, size_t size);

void PrivateKeyWrapperFree(PrivateKeyWrapper privateKeyWrapper);

HandleRetWrapper PrivateKeyWrapperGetG2Power(
    PrivateKeyWrapper privateKeyWrapper,
    BytesWrapper g2ElementWrapper);

IntRetWrapper PrivateKeyWrapperIsZero(PrivateKeyWrapper privateKeyWrapper);

IntRetWrapper PrivateKeyWrapperEquals(
    PrivateKeyWrapper privateKeyWrapper,
    PrivateKeyWrapper privateKeyOtherWrapper);

HandleRetWrapper PrivateKeyWrapperAggregate(PrivateKeyWrapper *keys, int num);

HandleRetWrapper PrivateKeyWrapperMulG1Element(
    PrivateKeyWrapper privateKeyWrapper,
    BytesWrapper g1ElementWrapper);

HandleRetWrapper PrivateKeyWrapperMulG2Element(
    PrivateKeyWrapper privateKeyWrapper,
    BytesWrapper g2ElementWrapper);

HandleRetWrapper PrivateKeyWrapperSerialize(PrivateKeyWrapper privateKeyWrapper);

HandleRetWrapper PrivateKeyWrapperGetG1Element(
    PrivateKeyWrapper privateKeyWrapper);

HandleRetWrapper PrivateKeyWrapperSignG2(
    PrivateKeyWrapper privateKeyWrapper,
    BytesWrapper msgWrapper,
    BytesWrapper dstWrapper);

#ifdef __cplusplus
}
#endif
#endif  // BLS_GO_BINDINGS_PRIVATE_KEY_WRAPPER_H