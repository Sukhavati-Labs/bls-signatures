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

PrivateKeyWrapper BasicSchemeMPLWrapperGenKey(BasicSchemeMPLWrapper basicScheme,const uint8_t * seedBuffer,size_t size){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    vector<uint8_t> seed(seedBuffer,seedBuffer+size);
    bls::PrivateKey *privateKey = new bls::PrivateKey((*basicSchemeMpl).KeyGen(seed));
    return (PrivateKeyWrapper)(privateKey);
}

BytesWrapper BasicSchemeMPLWrapperAggregateG1Element(BasicSchemeMPLWrapper basicScheme,const BytesWrapper * pubKeys,int num){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    std::vector<bls::G1Element> publicKeys;
    for (int i = 0 ;i < num ;i++){
        bls::Bytes *bytes =  (bls::Bytes*)(pubKeys[i]);
        bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
        publicKeys.push_back(g1);
    }
    bls::G1Element augG1 = (*basicSchemeMpl).Aggregate(publicKeys);
    bls::Bytes *bytes = new bls::Bytes(augG1.Serialize());
    return (BytesWrapper)(bytes);
}

BytesWrapper BasicSchemeMPLWrapperSign(BasicSchemeMPLWrapper basicScheme,PrivateKeyWrapper privateKeyWrapper,const uint8_t * message,size_t size){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    bls::PrivateKey *privateKey = (bls::PrivateKey*) privateKeyWrapper;
    vector<uint8_t> msg(message,message+size);
    bls::G2Element sig = (*basicSchemeMpl).Sign(*privateKey,msg);
    std::vector<uint8_t> sigBytes = sig.Serialize();

    uint8_t * n = (uint8_t*)malloc(sigBytes.size());
    memcpy(n,sigBytes.data(),sigBytes.size());
    bls::Bytes *bytes = new bls::Bytes(n,sigBytes.size());
//    bls::G2Element g2 = bls::G2Element::FromBytes(*bytes);
//    std::cout << "-----------\n1:\n"
//              << bls::Util::HexStr(g2.Serialize())
//              <<"\n2:\n"
//              <<bls::Util::HexStr(sig.Serialize())
//              << std::endl;
//    if (g2 != sig ){
//
//    }
    return (BytesWrapper)(bytes);
}


int BasicSchemeMPLWrapperVerify(BasicSchemeMPLWrapper basicScheme,BytesWrapper publicKeyBytes,const uint8_t * message,size_t size,BytesWrapper signatureBytes){
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    bls::Bytes *pubBytes = (bls::Bytes*)publicKeyBytes;
    bls::Bytes *sigBytes = (bls::Bytes*)signatureBytes;
    std::cout<< "BasicSchemeMPLWrapperVerify:\npubkey:\n"
        << bls::Util::HexStr((*pubBytes).begin(),(*pubBytes).size())
        << "\nsig:\n"
        << bls::Util::HexStr((*sigBytes).begin(),(*sigBytes).size())
        << std::endl;

    bls::G2Element signature;
    bls::G1Element publicKey;
    //try{
        signature = bls::G2Element::FromBytes(*sigBytes);
        publicKey = bls::G1Element::FromBytes(*pubBytes);
    //}catch(...){
    //    return 0;
    //}
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