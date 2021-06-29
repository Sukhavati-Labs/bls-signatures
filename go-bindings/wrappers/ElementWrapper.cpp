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
#include "../../src/bls.hpp"
#include "BytesWrapper.h"
#include "ElementWrapper.h"

uint32_t G1ElementGetFingerprint(BytesWrapper publicKeyWrapper){
    bls::Bytes *b = (bls::Bytes*)publicKeyWrapper;
    bls::G1Element g1 = bls::G1Element::FromBytes(*b);
    return  g1.GetFingerprint();
}

BytesWrapper G1ElementAdd(BytesWrapper publicKeyWrapper,BytesWrapper publicKeyAddendWrapper){
    bls::Bytes *b = (bls::Bytes*)publicKeyWrapper;
    bls::Bytes *bAddend = (bls::Bytes*) publicKeyAddendWrapper;
    bls::G1Element g1 = bls::G1Element::FromBytes(*b);
    bls::G1Element g1Addend = bls::G1Element::FromBytes(*bAddend);
    bls::G1Element g1ret =  g1 + g1Addend;
    std::vector<uint8_t> ret = g1ret.Serialize();
    return BytesWrapperInit(ret.data(),ret.size());
}