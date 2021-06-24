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

BytesWrapper PrivateKeyWrapperSerialize(PrivateKeyWrapper privateKeyWrapper){
    bls::PrivateKey *key = reinterpret_cast<bls::PrivateKey*>(privateKeyWrapper);
    //bls::Bytes *bytes = new bls::Bytes((*key).Serialize());
    auto sigBytes = (*key).Serialize();
    uint8_t * n = (uint8_t*)malloc(sigBytes.size());
    memcpy(n,sigBytes.data(),sigBytes.size());
    bls::Bytes *bytes = new bls::Bytes(n,sigBytes.size());
    return (BytesWrapper)(bytes);
}

BytesWrapper PrivateKeyWrapperGetG1Element(PrivateKeyWrapper privateKeyWrapper){
    bls::PrivateKey *key = (bls::PrivateKey*)(privateKeyWrapper);
    bls::G1Element publicKey = (*key).GetG1Element();
    auto sigBytes = publicKey.Serialize();
    uint8_t * n = (uint8_t*)malloc(sigBytes.size());
    memcpy(n,sigBytes.data(),sigBytes.size());
    bls::Bytes *bytes = new bls::Bytes(n,sigBytes.size());
    //bls::Bytes *bytes = new bls::Bytes(publicKey.Serialize());
    return (BytesWrapper)(bytes);
}