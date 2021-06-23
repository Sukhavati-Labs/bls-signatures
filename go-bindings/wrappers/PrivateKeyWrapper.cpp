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
#include "relic_label.h"
#include "PrivateKeyWrapper.h"
#include "../src/privatekey.h"
#include "../../src/util.hpp"
#include "../../src/privatekey.hpp"

PrivateWrapper PrivateKeyWrapperFromBytes(const uint8_t *buffer,size_t size){
    bls::Bytes b bls::Bytes(buffer,size);
    bls::PrivateKey *privateKey = new bls::PrivateKey(bls::PrivateKey::FromBytes(b));
    return (void *)(privateKey);
}

void PrivateKeyWrapperFree(PrivateKeyWrapper privateKeyWrapper){
    bls::PrivateKey *privateKey = (bls::PrivateKey*) privateKeyWrapper;
    delete privateKey;
}