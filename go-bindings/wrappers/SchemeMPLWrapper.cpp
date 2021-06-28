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

#include "SchemeMPLWrapper.h"

#include "../../src/schemes.hpp"
#include "PrivateKeyWrapper.h"
#include "../../src/util.hpp"


BasicSchemeMPLWrapper BasicSchemeMPLWrapperInit(){
   bls::BasicSchemeMPL *basicSchemeMpl = new bls::BasicSchemeMPL();
   return (BasicSchemeMPLWrapper)(basicSchemeMpl);
}

PrivateKeyWrapper BasicSchemeMPLWrapperKeyGen(BasicSchemeMPLWrapper basicScheme,const uint8_t * seedBuffer,size_t size){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    vector<uint8_t> seed(seedBuffer,seedBuffer+size);
    bls::PrivateKey *privateKey = new bls::PrivateKey((*basicSchemeMpl).KeyGen(seed));
    return (PrivateKeyWrapper)(privateKey);
}

BytesWrapper BasicSchemeMPLWrapperAggregateG2Element(BasicSchemeMPLWrapper basicScheme,const BytesWrapper * signatures,int num){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    std::vector<bls::G2Element> sigs;
    for (int i = 0 ;i < num ;i++){
        bls::Bytes *bytes =  (bls::Bytes*)(signatures[i]);
        bls::G2Element g2 = bls::G2Element::FromBytes(*bytes);
        sigs.push_back(g2);
    }
    bls::G2Element augG2 = (*basicSchemeMpl).Aggregate(sigs);
    std::vector<uint8_t> g2 = augG2.Serialize();
    return BytesWrapperInit(g2.data(),g2.size());
}

BytesWrapper BasicSchemeMPLWrapperAggregateG1Element(BasicSchemeMPLWrapper basicScheme,const BytesWrapper * publicKeys,int num){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    std::vector<bls::G1Element> pubKeys;
    for (int i = 0 ;i < num ;i++){
        bls::Bytes *bytes =  (bls::Bytes*)(publicKeys[i]);
        bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
        pubKeys.push_back(g1);
    }
    bls::G1Element augG1 = (*basicSchemeMpl).Aggregate(pubKeys);
    std::vector<uint8_t> g1 = augG1.Serialize();
    return BytesWrapperInit(g1.data(),g1.size());
}

int BasicSchemeMPLWrapperAggregateVerify(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper * publicKeys,int keyNum,
    const BytesWrapper * messages,int msgNum,
    const BytesWrapper signature){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    std::vector<bls::G1Element> pubKeys;
    for (int i = 0 ;i < keyNum ;i++){
        bls::Bytes *bytes =  (bls::Bytes*)(publicKeys[i]);
        bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
        pubKeys.push_back(g1);
    }
    bls::Bytes *g2 = (bls::Bytes*)signature;
    bls::G2Element sig = bls::G2Element::FromBytes(*g2);
    std::vector<bls::Bytes>msgs;
    for (int i = 0 ;i < msgNum ;i++){
        bls::Bytes *bytes =  (bls::Bytes*)(messages[i]);
        msgs.push_back(*bytes);
    }
    if (basicSchemeMpl->AggregateVerify(pubKeys,msgs,sig)){
        return 1;
    }else{
        return 0;
    }

}

BytesWrapper BasicSchemeMPLWrapperSign(BasicSchemeMPLWrapper basicScheme,PrivateKeyWrapper privateKeyWrapper,const uint8_t * message,size_t size){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    bls::PrivateKey *privateKey = (bls::PrivateKey*) privateKeyWrapper;
    vector<uint8_t> msg(message,message+size);
    bls::G2Element sig = (*basicSchemeMpl).Sign(*privateKey,msg);
    std::vector<uint8_t> sigBytes = sig.Serialize();
    return BytesWrapperInit(sigBytes.data(),sigBytes.size());
}


int BasicSchemeMPLWrapperVerify(BasicSchemeMPLWrapper basicScheme,BytesWrapper publicKeyBytes,const uint8_t * message,size_t size,BytesWrapper signatureBytes){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    bls::Bytes *pubBytes = (bls::Bytes*)publicKeyBytes;
    bls::Bytes *sigBytes = (bls::Bytes*)signatureBytes;
    bls::G2Element signature;
    bls::G1Element publicKey;
    try{
        signature = bls::G2Element::FromBytes(*sigBytes);
        publicKey = bls::G1Element::FromBytes(*pubBytes);
    }catch(...){
        return 0;
    }
    vector<uint8_t> msg(message,message+size);

    if ((*basicSchemeMpl).Verify(publicKey,msg,signature)){
        return 1;
    }
    return 0;
}


AugSchemeMPLWrapper AugSchemeMPLWrapperInit(){
    bls::AugSchemeMPL *augSchemeMpl = new bls::AugSchemeMPL();
    return (AugSchemeMPLWrapper)(augSchemeMpl);
}

PrivateKeyWrapper AugSchemeMPLWrapperKeyGen(AugSchemeMPLWrapper augScheme,const uint8_t * seed,size_t size){
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL*) augScheme;
    std::vector<uint8_t> keySeed(seed,seed+size);
    bls::PrivateKey *privateKey = new bls::PrivateKey(augSchemeMpl->KeyGen(keySeed));
    return (PrivateKeyWrapper)(privateKey);
}

BytesWrapper AugSchemeMPLWrapperSign(
    BasicSchemeMPLWrapper augScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t * message,size_t size){
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL*) augScheme;
    bls::PrivateKey *privateKey = (bls::PrivateKey*) privateKeyWrapper;
    vector<uint8_t> msg(message,message+size);
    bls::G2Element sig = (*augSchemeMpl).Sign(*privateKey,msg);
    std::vector<uint8_t> sigBytes = sig.Serialize();
    return BytesWrapperInit(sigBytes.data(),sigBytes.size());
}

int AugSchemeMPLWrapperVerify(
    AugSchemeMPLWrapper augScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t * message,size_t size,
    BytesWrapper signatureBytes){
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL*) augScheme;
    bls::Bytes *pubBytes = (bls::Bytes*)publicKeyBytes;
    bls::Bytes *sigBytes = (bls::Bytes*)signatureBytes;
    bls::G2Element signature;
    bls::G1Element publicKey;
    try{
        signature = bls::G2Element::FromBytes(*sigBytes);
        publicKey = bls::G1Element::FromBytes(*pubBytes);
    }catch(...){
        return 0;
    }
    vector<uint8_t> msg(message,message+size);
    if ((*augSchemeMpl).Verify(publicKey,msg,signature)){
        return 1;
    }
    return 0;
}

PrivateKeyWrapper AugSchemeMPLDeriveChildSk(AugSchemeMPLWrapper augScheme,PrivateKeyWrapper master,uint32_t index){
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL*) augScheme;
    bls::PrivateKey * masterPrivateKey = (bls::PrivateKey*) master;
    bls::PrivateKey childSk = (*augSchemeMpl).DeriveChildSk(*masterPrivateKey,index);
    bls::PrivateKey *childPrivateKey = new bls::PrivateKey(childSk);
    return (void *)(childPrivateKey);
}

int AugSchemeMPLWrapperAggregateVerify(
    AugSchemeMPLWrapper augScheme,
    const BytesWrapper * publicKeys,int keyNum,
    const BytesWrapper * messages,int msgNum,
    const BytesWrapper signature){
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL*) augScheme;
    std::vector<bls::G1Element> pubKeys;
    for (int i = 0 ;i < keyNum ;i++){
        bls::Bytes *bytes =  (bls::Bytes*)(publicKeys[i]);
        bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
        pubKeys.push_back(g1);
    }
    bls::Bytes *g2 = (bls::Bytes*)signature;
    bls::G2Element sig = bls::G2Element::FromBytes(*g2);
    std::vector<bls::Bytes>msgs;
    for (int i = 0 ;i < msgNum ;i++){
        bls::Bytes *bytes =  (bls::Bytes*)(messages[i]);
        msgs.push_back(*bytes);
    }
    if (augSchemeMpl->AggregateVerify(pubKeys,msgs,sig)){
        return 1;
    }else{
        return 0;
    }

}

PopSchemeMPLWrapper PopSchemeMPLWrapperInit(){
    bls::PopSchemeMPL *popSchemeMpl = new bls::PopSchemeMPL();
    return (PopSchemeMPLWrapper)(popSchemeMpl);
}


PrivateKeyWrapper PopSchemeMPLWrapperKeyGen(PopSchemeMPLWrapper popScheme,const uint8_t * seed,size_t size){
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL*) popScheme;
    std::vector<uint8_t> keySeed(seed,seed+size);
    bls::PrivateKey *privateKey = new bls::PrivateKey(popSchemeMpl->KeyGen(keySeed));
    return (PrivateKeyWrapper)(privateKey);
}
