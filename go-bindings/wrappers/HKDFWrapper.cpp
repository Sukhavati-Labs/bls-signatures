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

#include "HKDFWrapper.h"

#include "../../src/bls.hpp"

BytesWrapper HKDF256Extract(BytesWrapper salt, BytesWrapper ikm)
{
    std::vector<uint8_t> out;
    bls::Bytes *saltBytes = reinterpret_cast<bls::Bytes *>(salt);
    bls::Bytes *ikmBytes = reinterpret_cast<bls::Bytes *>(ikm);
    bls::HKDF256::Extract(
        out.data(),
        saltBytes->begin(),
        saltBytes->size(),
        ikmBytes->begin(),
        ikmBytes->size());
    return BytesWrapperInit(out.data(), out.size());
}

BytesWrapper HKDF256Expand(BytesWrapper prk, BytesWrapper info)
{
    //    std::vector<uint8_t> out;
    //    bls::Bytes *saltBytes = (bls::Bytes*)(prk);
    //    bls::Bytes *ikmBytes  = (bls::Bytes*)(info);
    //    bls::HKDF256::Expand(out.data(),saltBytes->begin(),saltBytes->size(),ikmBytes->begin(),ikmBytes->size());
    //    return BytesWrapperInit(out.data(),out.size());
    return NULL;
}