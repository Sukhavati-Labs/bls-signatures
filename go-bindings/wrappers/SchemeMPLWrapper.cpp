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
#include "SchemeMPLWrapper.h"
#include "PrivateKeyWrapper.h"
#include "../../src/bls.hpp"

BasicSchemeMPLWrapper BasicSchemeMPLWrapperInit(){
   bls::BasicSchemeMPL *basicSchemeMpl = new bls::BasicSchemeMPL();
   return (void*)basicSchemeMpl;
}

PrivateKeyWrapper BasicSchemeMPLWrapperGenKey(BasicSchemeMPLWrapper basicScheme,const uint8_t * seedBuffer,size_t size){
    vector<uint8_t> seed(seedBuffer,seedBuffer+size);
    bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL*) basicScheme;
    bls::PrivateKey *privateKey = new bls::PrivateKey((*basicSchemeMpl).KeyGen(seed));
    return (void*)(privateKey);
}

AugSchemeMPLWrapper AugSchemeMPLWrapperInit(){
    bls::AugSchemeMPL *augSchemeMpl = new bls::AugSchemeMPL();
    return (void*)augSchemeMpl;
}