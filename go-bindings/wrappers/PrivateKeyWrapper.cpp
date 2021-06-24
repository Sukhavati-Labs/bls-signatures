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
#include "../../src/util.hpp"
#include "../../src/privatekey.hpp"

PrivateKeyWrapper PrivateKeyWrapperFromBytes(const uint8_t *buffer,size_t size){
    std::vector<uint8_t>b(buffer,buffer+size);
    bls::PrivateKey *privateKey = new bls::PrivateKey(bls::PrivateKey::FromByteVector(b));
    return reinterpret_cast<void *>(privateKey);
}

void PrivateKeyWrapperFree(PrivateKeyWrapper privateKeyWrapper){
    bls::PrivateKey *privateKey = (bls::PrivateKey*) privateKeyWrapper;
    delete privateKey;
}

int PrivateKeyWrapperIsZero(PrivateKeyWrapper privateKeyWrapper){
    bls::PrivateKey *privateKey = (bls::PrivateKey*) privateKeyWrapper;
    if ((*privateKey).IsZero()){
       return 1;
    }
    return 0;
}

PrivateKeyWrapper PrivateKeyWrapperAggregate(const PrivateKeyWrapper *keys,int num){
    bls::PrivateKey **keyList =  (bls::PrivateKey**) keys;
    std::vector<bls::PrivateKey>keyVec;
    for (int i=0;i<num ;i++){
        bls::PrivateKey *key = keyList[i];
        keyVec.push_back(*key);
    }
    bls::PrivateKey *augKey = new bls::PrivateKey(bls::PrivateKey::Aggregate(keyVec));
    return  reinterpret_cast<void*>(augKey);
}

uint8_t* PrivateKeyWrapperSerialize(PrivateKeyWrapper privateKeyWrapper){
    bls::PrivateKey *key = reinterpret_cast<bls::PrivateKey*>(privateKeyWrapper);
    std::vector<uint8_t> buffer = (*key).Serialize();
    uint8_t *b = (uint8_t*)malloc(buffer.size()+1);
    memcpy(b,buffer.data(),32);
    return b;
}

