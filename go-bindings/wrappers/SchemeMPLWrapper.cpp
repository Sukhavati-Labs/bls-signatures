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
#include "../../src/util.hpp"
#include "PrivateKeyWrapper.h"

BasicSchemeMPLWrapper BasicSchemeMPLWrapperInit()
{
    bls::BasicSchemeMPL *basicSchemeMpl = new bls::BasicSchemeMPL();
    return (BasicSchemeMPLWrapper)(basicSchemeMpl);
}

HandleRetWrapper BasicSchemeMPLWrapperKeyGen(
    BasicSchemeMPLWrapper basicScheme,
    const uint8_t *seedBuffer,
    size_t size)
{
    HandleRetWrapper ret = {0};
    try {
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        vector<uint8_t> seed(seedBuffer, seedBuffer + size);
        bls::PrivateKey *privateKey =
            new bls::PrivateKey((*basicSchemeMpl).KeyGen(seed));
        ret.handle =  (PrivateKeyWrapper)(privateKey);
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
     return ret;
}

HandleRetWrapper BasicSchemeMPLWrapperAggregateG2Element(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper *signatures,
    int num)
{
    HandleRetWrapper  ret = {0};
    try{
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        std::vector<bls::G2Element> sigs;
        for (int i = 0; i < num; i++) {
            bls::Bytes *bytes = (bls::Bytes *)(signatures[i]);
            bls::G2Element g2 = bls::G2Element::FromBytes(*bytes);
            sigs.push_back(g2);
        }
        bls::G2Element augG2 = (*basicSchemeMpl).Aggregate(sigs);
        std::vector<uint8_t> g2 = augG2.Serialize();
        ret.handle = BytesWrapperInit(g2.data(), g2.size());
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper BasicSchemeMPLWrapperAggregateG1Element(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper *publicKeys,
    int num)
{
    HandleRetWrapper ret = {0};
    try {
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        std::vector<bls::G1Element> pubKeys;
        for (int i = 0; i < num; i++) {
            bls::Bytes *bytes = (bls::Bytes *)(publicKeys[i]);
            bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
            pubKeys.push_back(g1);
        }
        bls::G1Element augG1 = (*basicSchemeMpl).Aggregate(pubKeys);
        std::vector<uint8_t> g1 = augG1.Serialize();
        ret.handle = BytesWrapperInit(g1.data(), g1.size());
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

IntRetWrapper BasicSchemeMPLWrapperAggregateVerify(
    BasicSchemeMPLWrapper basicScheme,
    const BytesWrapper *publicKeys,
    int keyNum,
    const BytesWrapper *messages,
    int msgNum,
    const BytesWrapper signature)
{
    IntRetWrapper ret = {0};
    try {
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        std::vector<bls::G1Element> pubKeys;
        for (int i = 0; i < keyNum; i++) {
            bls::Bytes *bytes = (bls::Bytes *)(publicKeys[i]);
            bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
            pubKeys.push_back(g1);
        }
        bls::Bytes *g2 = (bls::Bytes *)signature;
        bls::G2Element sig = bls::G2Element::FromBytes(*g2);
        std::vector<bls::Bytes> msgs;
        for (int i = 0; i < msgNum; i++) {
            bls::Bytes *bytes = (bls::Bytes *)(messages[i]);
            msgs.push_back(*bytes);
        }
        if (basicSchemeMpl->AggregateVerify(pubKeys, msgs, sig)) {
            ret.ret = 1;
        } else {
            ret.ret = 0;
        }
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper BasicSchemeMPLWrapperSign(
    BasicSchemeMPLWrapper basicScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t *message,
    size_t size)
{
    HandleRetWrapper ret = {0};
    try {
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        bls::PrivateKey *privateKey = (bls::PrivateKey *)privateKeyWrapper;
        vector<uint8_t> msg(message, message + size);
        bls::G2Element sig = (*basicSchemeMpl).Sign(*privateKey, msg);
        std::vector<uint8_t> sigBytes = sig.Serialize();
        ret.handle = BytesWrapperInit(sigBytes.data(), sigBytes.size());
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

IntRetWrapper BasicSchemeMPLWrapperVerify(
    BasicSchemeMPLWrapper basicScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t *message,
    size_t size,
    BytesWrapper signatureBytes)
{
    IntRetWrapper ret = {0};
    try {
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        bls::Bytes *pubBytes = (bls::Bytes *)publicKeyBytes;
        bls::Bytes *sigBytes = (bls::Bytes *)signatureBytes;
        bls::G2Element  signature = bls::G2Element::FromBytes(*sigBytes);
        bls::G1Element publicKey = bls::G1Element::FromBytes(*pubBytes);
        vector<uint8_t> msg(message, message + size);
        if ((*basicSchemeMpl).Verify(publicKey, msg, signature)) {
            ret.ret = 1;
        }else{
            ret.ret = 0;
        }
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper BasicSchemeMPLDeriveChildSk(
    BasicSchemeMPLWrapper basicScheme,
    PrivateKeyWrapper master,
    uint32_t index)
{
    HandleRetWrapper ret = {0};
    try {
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        bls::PrivateKey *masterPrivateKey = (bls::PrivateKey *)master;
        bls::PrivateKey childSk =
            (*basicSchemeMpl).DeriveChildSk(*masterPrivateKey, index);
        bls::PrivateKey *childPrivateKey = new bls::PrivateKey(childSk);
        ret.handle = (PrivateKeyWrapper)(childPrivateKey);
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper BasicSchemeMPLDeriveChildSkUnhardened(
    BasicSchemeMPLWrapper basicScheme,
    PrivateKeyWrapper master,
    uint32_t index)
{
    HandleRetWrapper ret = {0};
    try {
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        bls::PrivateKey *masterPrivateKey = (bls::PrivateKey *)master;
        bls::PrivateKey childSk =
            (*basicSchemeMpl).DeriveChildSkUnhardened(*masterPrivateKey, index);
        bls::PrivateKey *childPrivateKey = new bls::PrivateKey(childSk);
        ret.handle =  (PrivateKeyWrapper)(childPrivateKey);
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper BasicSchemeMPLDeriveChildPkUnhardened(
    BasicSchemeMPLWrapper basicScheme,
    BytesWrapper master,
    uint32_t index)
{
    HandleRetWrapper ret = {0};
    try {
        bls::BasicSchemeMPL *basicSchemeMpl = (bls::BasicSchemeMPL *)basicScheme;
        bls::G1Element *masterPublicKey = (bls::G1Element *)master;
        bls::G1Element childPk =
            (*basicSchemeMpl).DeriveChildPkUnhardened(*masterPublicKey, index);
        std::vector<uint8_t> pk = childPk.Serialize();
        ret.handle = BytesWrapperInit(pk.data(), pk.size());
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

AugSchemeMPLWrapper AugSchemeMPLWrapperInit()
{
    bls::AugSchemeMPL *augSchemeMpl = new bls::AugSchemeMPL();
    return (AugSchemeMPLWrapper)(augSchemeMpl);
}

HandleRetWrapper AugSchemeMPLWrapperKeyGen(
    AugSchemeMPLWrapper augScheme,
    const uint8_t *seed,
    size_t size)
{
    HandleRetWrapper ret = {0};
    try{
        bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
        std::vector<uint8_t> keySeed(seed, seed + size);
        bls::PrivateKey *privateKey =
            new bls::PrivateKey(augSchemeMpl->KeyGen(keySeed));
        ret.handle= (PrivateKeyWrapper)(privateKey);
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper AugSchemeMPLWrapperSign(
    BasicSchemeMPLWrapper augScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t *message,
    size_t size)
{
    HandleRetWrapper ret = {0};
    try {
        bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
        bls::PrivateKey *privateKey = (bls::PrivateKey *)privateKeyWrapper;
        vector<uint8_t> msg(message, message + size);
        bls::G2Element sig = (*augSchemeMpl).Sign(*privateKey, msg);
        std::vector<uint8_t> sigBytes = sig.Serialize();
        ret.handle = BytesWrapperInit(sigBytes.data(), sigBytes.size());
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper AugSchemeMPLWrapperPrependingSign(
    AugSchemeMPLWrapper augScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t *message,
    size_t size,
    BytesWrapper publicKeyWrapper)
{
    HandleRetWrapper ret = {0};
    try {
        bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
        bls::PrivateKey *privateKey = (bls::PrivateKey *)privateKeyWrapper;
        bls::Bytes *g1Bytes = (bls::Bytes *)publicKeyWrapper;
        vector<uint8_t> msg(message, message + size);
        bls::G1Element g1 = bls::G1Element::FromBytes(*g1Bytes);
        bls::G2Element sig = (*augSchemeMpl).Sign(*privateKey, msg, g1);
        std::vector<uint8_t> sigBytes = sig.Serialize();
        ret.handle = BytesWrapperInit(sigBytes.data(), sigBytes.size());
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

IntRetWrapper AugSchemeMPLWrapperVerify(
    AugSchemeMPLWrapper augScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t *message,
    size_t size,
    BytesWrapper signatureBytes)
{
    IntRetWrapper ret = {0};
    try {
        bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
        bls::Bytes *pubBytes = (bls::Bytes *)publicKeyBytes;
        bls::Bytes *sigBytes = (bls::Bytes *)signatureBytes;
        bls::G2Element  signature = bls::G2Element::FromBytes(*sigBytes);
        bls::G1Element  publicKey = bls::G1Element::FromBytes(*pubBytes);
        vector<uint8_t> msg(message, message + size);
        if ((*augSchemeMpl).Verify(publicKey, msg, signature)) {
            ret.ret = 1;
        }else{
            ret.ret = 0;
        }
    } catch (std::exception &e) {
        ret.err = strdup(e.what());
    }
    return ret;
}

HandleRetWrapper AugSchemeMPLDeriveChildSk(
    AugSchemeMPLWrapper augScheme,
    PrivateKeyWrapper master,
    uint32_t index)
{
    bls::AugSchemeMPL *augSchemeMpl = reinterpret_cast<bls::AugSchemeMPL *>(augScheme);
    bls::PrivateKey *masterPrivateKey = reinterpret_cast<bls::PrivateKey *>(master);
    HandleRetWrapper ret = {0};
    try {
        bls::PrivateKey childSk =
            (*augSchemeMpl).DeriveChildSk(*masterPrivateKey, index);
        bls::PrivateKey *childPrivateKey = new bls::PrivateKey(childSk);
        ret.handle = reinterpret_cast<void*>(childPrivateKey);
    }catch (std::exception &e){
        ret.err = strdup(e.what());
    }
    return ret;
}

PrivateKeyWrapper AugSchemeMPLDeriveChildSkUnhardened(
    AugSchemeMPLWrapper augScheme,
    PrivateKeyWrapper master,
    uint32_t index)
{
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
    bls::PrivateKey *masterPrivateKey = (bls::PrivateKey *)master;
    bls::PrivateKey childSk =
        (*augSchemeMpl).DeriveChildSkUnhardened(*masterPrivateKey, index);
    bls::PrivateKey *childPrivateKey = new bls::PrivateKey(childSk);
    return (void *)(childPrivateKey);
}

BytesWrapper AugSchemeMPLDeriveChildPkUnhardened(
    AugSchemeMPLWrapper augScheme,
    BytesWrapper master,
    uint32_t index)
{
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
    bls::G1Element *masterPublicKey = (bls::G1Element *)master;
    bls::G1Element childPk =
        (*augSchemeMpl).DeriveChildPkUnhardened(*masterPublicKey, index);
    std::vector<uint8_t> pk = childPk.Serialize();
    return BytesWrapperInit(pk.data(), pk.size());
}

BytesWrapper AugSchemeMPLWrapperAggregateG1Element(
    AugSchemeMPLWrapper augScheme,
    const BytesWrapper *publicKeys,
    int num)
{
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
    std::vector<bls::G1Element> pubKeys;
    for (int i = 0; i < num; i++) {
        bls::Bytes *bytes = (bls::Bytes *)(publicKeys[i]);
        bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
        pubKeys.push_back(g1);
    }
    bls::G1Element g1 = (*augSchemeMpl).Aggregate(pubKeys);
    vector<uint8_t> sigBytes = g1.Serialize();
    return BytesWrapperInit(sigBytes.data(), sigBytes.size());
}

BytesWrapper AugSchemeMPLWrapperAggregateG2Element(
    AugSchemeMPLWrapper augScheme,
    const BytesWrapper *signatures,
    int num)
{
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
    std::vector<bls::G2Element> signs;
    for (int i = 0; i < num; i++) {
        bls::Bytes *bytes = (bls::Bytes *)(signatures[i]);
        bls::G2Element g2 = bls::G2Element::FromBytes(*bytes);
        signs.push_back(g2);
    }
    bls::G2Element g2 = (*augSchemeMpl).Aggregate(signs);
    vector<uint8_t> sigBytes = g2.Serialize();
    return BytesWrapperInit(sigBytes.data(), sigBytes.size());
}

int AugSchemeMPLWrapperAggregateVerify(
    AugSchemeMPLWrapper augScheme,
    const BytesWrapper *publicKeys,
    int keyNum,
    const BytesWrapper *messages,
    int msgNum,
    const BytesWrapper signature)
{
    bls::AugSchemeMPL *augSchemeMpl = (bls::AugSchemeMPL *)augScheme;
    std::vector<bls::G1Element> pubKeys;
    for (int i = 0; i < keyNum; i++) {
        bls::Bytes *bytes = (bls::Bytes *)(publicKeys[i]);
        bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
        pubKeys.push_back(g1);
    }
    bls::Bytes *g2 = (bls::Bytes *)signature;
    bls::G2Element sig = bls::G2Element::FromBytes(*g2);
    std::vector<bls::Bytes> msgs;
    for (int i = 0; i < msgNum; i++) {
        bls::Bytes *bytes = (bls::Bytes *)(messages[i]);
        msgs.push_back(*bytes);
    }
    if (augSchemeMpl->AggregateVerify(pubKeys, msgs, sig)) {
        return 1;
    } else {
        return 0;
    }
}

PopSchemeMPLWrapper PopSchemeMPLWrapperInit()
{
    bls::PopSchemeMPL *popSchemeMpl = new bls::PopSchemeMPL();
    return (PopSchemeMPLWrapper)(popSchemeMpl);
}

PrivateKeyWrapper PopSchemeMPLWrapperKeyGen(
    PopSchemeMPLWrapper popScheme,
    const uint8_t *seed,
    size_t size)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    std::vector<uint8_t> keySeed(seed, seed + size);
    bls::PrivateKey *privateKey =
        new bls::PrivateKey(popSchemeMpl->KeyGen(keySeed));
    return (PrivateKeyWrapper)(privateKey);
}

BytesWrapper PopSchemeMPLWrapperSign(
    PopSchemeMPLWrapper popScheme,
    PrivateKeyWrapper privateKeyWrapper,
    const uint8_t *message,
    size_t size)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    bls::PrivateKey *privateKey = (bls::PrivateKey *)privateKeyWrapper;
    vector<uint8_t> msg(message, message + size);
    bls::G2Element sig = (*popSchemeMpl).Sign(*privateKey, msg);
    std::vector<uint8_t> sigBytes = sig.Serialize();
    return BytesWrapperInit(sigBytes.data(), sigBytes.size());
}

int PopSchemeMPLWrapperVerify(
    PopSchemeMPLWrapper popScheme,
    BytesWrapper publicKeyBytes,
    const uint8_t *message,
    size_t size,
    BytesWrapper signatureBytes)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    bls::Bytes *pubBytes = (bls::Bytes *)publicKeyBytes;
    bls::Bytes *sigBytes = (bls::Bytes *)signatureBytes;
    bls::G2Element signature;
    bls::G1Element publicKey;
    try {
        signature = bls::G2Element::FromBytes(*sigBytes);
        publicKey = bls::G1Element::FromBytes(*pubBytes);
    } catch (...) {
        return 0;
    }
    vector<uint8_t> msg(message, message + size);
    if ((*popSchemeMpl).Verify(publicKey, msg, signature)) {
        return 1;
    }
    return 0;
}

BytesWrapper PopSchemeMPLWrapperAggregateG1Element(
    PopSchemeMPLWrapper popScheme,
    const BytesWrapper *publicKeys,
    int num)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    std::vector<bls::G1Element> pubKeys;
    for (int i = 0; i < num; i++) {
        bls::Bytes *bytes = (bls::Bytes *)(publicKeys[i]);
        bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
        pubKeys.push_back(g1);
    }
    bls::G1Element g1 = (*popSchemeMpl).Aggregate(pubKeys);
    vector<uint8_t> sigBytes = g1.Serialize();
    return BytesWrapperInit(sigBytes.data(), sigBytes.size());
}

BytesWrapper PopSchemeMPLWrapperAggregateG2Element(
    PopSchemeMPLWrapper popScheme,
    const BytesWrapper *signatures,
    int num)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    std::vector<bls::G2Element> signs;
    for (int i = 0; i < num; i++) {
        bls::Bytes *bytes = (bls::Bytes *)(signatures[i]);
        bls::G2Element g2 = bls::G2Element::FromBytes(*bytes);
        signs.push_back(g2);
    }
    bls::G2Element g2 = (*popSchemeMpl).Aggregate(signs);
    vector<uint8_t> sigBytes = g2.Serialize();
    return BytesWrapperInit(sigBytes.data(), sigBytes.size());
}

int PopSchemeMPLWrapperAggregateVerify(
    PopSchemeMPLWrapper popScheme,
    const BytesWrapper *publicKeys,
    int keyNum,
    const BytesWrapper *messages,
    int msgNum,
    const BytesWrapper signature)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    std::vector<bls::G1Element> pubKeys;
    for (int i = 0; i < keyNum; i++) {
        bls::Bytes *bytes = (bls::Bytes *)(publicKeys[i]);
        bls::G1Element g1 = bls::G1Element::FromBytes(*bytes);
        pubKeys.push_back(g1);
    }
    bls::Bytes *g2 = (bls::Bytes *)signature;
    bls::G2Element sig = bls::G2Element::FromBytes(*g2);
    std::vector<bls::Bytes> msgs;
    for (int i = 0; i < msgNum; i++) {
        bls::Bytes *bytes = (bls::Bytes *)(messages[i]);
        msgs.push_back(*bytes);
    }
    if (popSchemeMpl->AggregateVerify(pubKeys, msgs, sig)) {
        return 1;
    } else {
        return 0;
    }
}

PrivateKeyWrapper PopSchemeMPLDeriveChildSk(
    PopSchemeMPLWrapper popScheme,
    PrivateKeyWrapper master,
    uint32_t index)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    bls::PrivateKey *masterPrivateKey = (bls::PrivateKey *)master;
    bls::PrivateKey childSk =
        (*popSchemeMpl).DeriveChildSk(*masterPrivateKey, index);
    bls::PrivateKey *childPrivateKey = new bls::PrivateKey(childSk);
    return (void *)(childPrivateKey);
}

PrivateKeyWrapper PopSchemeMPLDeriveChildSkUnhardened(
    PopSchemeMPLWrapper popScheme,
    PrivateKeyWrapper master,
    uint32_t index)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    bls::PrivateKey *masterPrivateKey = (bls::PrivateKey *)master;
    bls::PrivateKey childSk =
        (*popSchemeMpl).DeriveChildSkUnhardened(*masterPrivateKey, index);
    bls::PrivateKey *childPrivateKey = new bls::PrivateKey(childSk);
    return (void *)(childPrivateKey);
}

BytesWrapper PopSchemeMPLDeriveChildPkUnhardened(
    PopSchemeMPLWrapper popScheme,
    BytesWrapper master,
    uint32_t index)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    bls::G1Element *masterPublicKey = (bls::G1Element *)master;
    bls::G1Element childPk =
        (*popSchemeMpl).DeriveChildPkUnhardened(*masterPublicKey, index);
    std::vector<uint8_t> pk = childPk.Serialize();
    return BytesWrapperInit(pk.data(), pk.size());
}

BytesWrapper PopSchemeMPLPopProve(
    PopSchemeMPLWrapper popScheme,
    PrivateKeyWrapper privateKey)
{
    bls::PopSchemeMPL *popSchemeMpl = (bls::PopSchemeMPL *)popScheme;
    bls::PrivateKey *key = (bls::PrivateKey *)privateKey;
    bls::G2Element prove = (*popSchemeMpl).PopProve(*key);
    std::vector<uint8_t> pk = prove.Serialize();
    return BytesWrapperInit(pk.data(), pk.size());
}