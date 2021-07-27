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

#include "PrivateKeyWrapper.h"

#include "../../src/privatekey.hpp"
#include "../../src/util.hpp"
#include "relic.h"
#include "relic_label.h"

HandleRetWrapper PrivateKeyWrapperFromBytes(const uint8_t *buffer, size_t size)
{
    std::vector<uint8_t> b(buffer, buffer + size);
    HandleRetWrapper ret = {0};
    try {
        bls::PrivateKey *privateKey =
            new bls::PrivateKey(bls::PrivateKey::FromByteVector(b));
        ret.handle = reinterpret_cast<void *>(privateKey);
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

void PrivateKeyWrapperFree(PrivateKeyWrapper privateKeyWrapper)
{
    bls::PrivateKey *privateKey =
        reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
    delete privateKey;
}

HandleRetWrapper PrivateKeyWrapperGetG2Power(
    PrivateKeyWrapper privateKeyWrapper,
    BytesWrapper g2ElementWrapper)
{
    bls::PrivateKey *privateKey =
        reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
    HandleRetWrapper ret = {0};
    try {
        bls::Bytes *b = reinterpret_cast<bls::Bytes *>(g2ElementWrapper);
        bls::G2Element g2 = bls::G2Element::FromBytes(*b);
        bls::G2Element g2r = (*privateKey).GetG2Power(g2);
        std::vector<uint8_t> data = g2r.Serialize();
        ret.handle = BytesWrapperInit(data.data(), data.size());
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

IntRetWrapper PrivateKeyWrapperIsZero(PrivateKeyWrapper privateKeyWrapper)
{
    bls::PrivateKey *privateKey =
        reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
    IntRetWrapper ret = {0};
    try {
        if ((*privateKey).IsZero()) {
            ret.ret = 1;
        } else {
            ret.ret = 0;
        }
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
        ret.ret = 0;
    }
    return ret;
}

IntRetWrapper PrivateKeyWrapperEquals(
    PrivateKeyWrapper privateKeyWrapper,
    PrivateKeyWrapper privateKeyOtherWrapper)
{
    bls::PrivateKey *privateKey =
        reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
    bls::PrivateKey *privateKeyOther =
        reinterpret_cast<bls::PrivateKey *>(privateKeyOtherWrapper);
    IntRetWrapper ret = {0};
    try {
        if ((*privateKey) == (*privateKeyOther)) {
            ret.ret = 1;
        } else {
            ret.ret = 0;
        }
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper PrivateKeyWrapperAggregate(PrivateKeyWrapper *keys, int num)
{
    bls::PrivateKey **keyList = reinterpret_cast<bls::PrivateKey **>(keys);
    std::vector<bls::PrivateKey> keyVec;

    for (int i = 0; i < num; i++) {
        bls::PrivateKey *key = keyList[i];
        keyVec.push_back(*key);
    }
    HandleRetWrapper ret = {0};
    try {
        bls::PrivateKey *augKey =
            new bls::PrivateKey(bls::PrivateKey::Aggregate(keyVec));
        ret.handle = reinterpret_cast<void *>(augKey);
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}
HandleRetWrapper PrivateKeyWrapperMulG1Element(
    PrivateKeyWrapper privateKeyWrapper,
    BytesWrapper g1ElementWrapper)
{
    bls::PrivateKey *key =
        reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
    HandleRetWrapper ret = {0};
    bls::Bytes *b = reinterpret_cast<bls::Bytes *>(g1ElementWrapper);
    try {
        bls::G1Element g1 = bls::G1Element::FromBytes(*b);
        bls::G1Element g1r = (*key) * g1;
        std::vector<uint8_t> data = g1r.Serialize();
        ret.handle = BytesWrapperInit(data.data(), data.size());
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper PrivateKeyWrapperMulG2Element(
    PrivateKeyWrapper privateKeyWrapper,
    BytesWrapper g2ElementWrapper)
{
    bls::PrivateKey *key =
        reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
    HandleRetWrapper ret = {0};
    bls::Bytes *b = reinterpret_cast<bls::Bytes *>(g2ElementWrapper);
    try {
        bls::G2Element g2 = bls::G2Element::FromBytes(*b);
        bls::G2Element g2r = (*key) * g2;
        std::vector<uint8_t> data = g2r.Serialize();
        ret.handle = BytesWrapperInit(data.data(), data.size());
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper PrivateKeyWrapperSerialize(PrivateKeyWrapper privateKeyWrapper)
{
    HandleRetWrapper ret = {0};
    try {
        bls::PrivateKey *key =
            reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
        std::vector<uint8_t> sigBytes = (*key).Serialize();
        ret.handle = BytesWrapperInit(sigBytes.data(), sigBytes.size());
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper PrivateKeyWrapperGetG1Element(
    PrivateKeyWrapper privateKeyWrapper)
{
    bls::PrivateKey *key =
        reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
    HandleRetWrapper ret = {0};
    try {
        bls::G1Element publicKey = (*key).GetG1Element();
        std::vector<uint8_t> sigBytes = publicKey.Serialize();
        ret.handle = BytesWrapperInit(sigBytes.data(), sigBytes.size());
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper PrivateKeyWrapperSignG2(
    PrivateKeyWrapper privateKeyWrapper,
    BytesWrapper msgWrapper,
    BytesWrapper dstWrapper)
{
    bls::PrivateKey *key =
        reinterpret_cast<bls::PrivateKey *>(privateKeyWrapper);
    HandleRetWrapper ret = {0};
    try {
        bls::G1Element publicKey = (*key).GetG1Element();
        std::vector<uint8_t> sigBytes = publicKey.Serialize();
        ret.handle = BytesWrapperInit(sigBytes.data(), sigBytes.size());
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}