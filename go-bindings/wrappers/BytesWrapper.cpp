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

#include "relic.h"
#include "../../src/util.hpp"
#include "BytesWrapper.h"

BytesWrapper BytesWrapperInit(const uint8_t * buffer ,size_t bufferSize){
    bls::Bytes * bytesWrapper =  new bls::Bytes(buffer,bufferSize);
    return reinterpret_cast<void *>(bytesWrapper);
}

void BytesWrapperFree(BytesWrapper bytesWrapper){
    bls::Bytes *b = (bls::Bytes *) bytesWrapper;
    delete b;
}

size_t BytesWrapperSize(BytesWrapper bytesWrapper){
    bls::Bytes *b = (bls::Bytes *) bytesWrapper;
    return b->size();
}

const uint8_t * BytesWrapperBegin(BytesWrapper bytesWrapper){
    bls::Bytes *b = (bls::Bytes *) bytesWrapper;
    return b->begin();
}

uint8_t BytesWrapperIndex(BytesWrapper bytesWrapper,int index){
    bls::Bytes *b = (bls::Bytes *) bytesWrapper;
    uint8_t c = (*b)[index];
    return c;
}