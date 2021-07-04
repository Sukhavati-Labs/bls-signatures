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

#include "BytesWrapper.h"

#include "../../src/util.hpp"
#include "relic.h"

BytesWrapper BytesWrapperInit(const uint8_t *buffer, size_t bufferSize)
{
    // safe use buffer copy
    uint8_t *bufferDup = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    memcpy(bufferDup, buffer, bufferSize);
    bls::Bytes *bytesWrapper = new bls::Bytes(bufferDup, bufferSize);
    return reinterpret_cast<void *>(bytesWrapper);
}

void BytesWrapperFree(BytesWrapper bytesWrapper)
{
    bls::Bytes *b = reinterpret_cast<bls::Bytes *>(bytesWrapper);
    uint8_t *buffer = const_cast<uint8_t *>(b->begin());
    free(buffer);
    delete b;
}

size_t BytesWrapperSize(BytesWrapper bytesWrapper)
{
    bls::Bytes *b = reinterpret_cast<bls::Bytes *>(bytesWrapper);
    return b->size();
}

const uint8_t *BytesWrapperBegin(BytesWrapper bytesWrapper)
{
    bls::Bytes *b = reinterpret_cast<bls::Bytes *>(bytesWrapper);
    return b->begin();
}

const uint8_t *BytesWrapperEnd(BytesWrapper bytesWrapper)
{
    bls::Bytes *b = reinterpret_cast<bls::Bytes *>(bytesWrapper);
    return b->end();
}

uint8_t BytesWrapperIndex(BytesWrapper bytesWrapper, int index)
{
    bls::Bytes *b = reinterpret_cast<bls::Bytes *>(bytesWrapper);
    uint8_t c = (*b)[index];
    return c;
}