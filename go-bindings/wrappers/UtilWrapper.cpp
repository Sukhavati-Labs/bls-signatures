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

#include "UtilWrapper.h"
#include "BytesWrapper.h"
#include "../../src/util.hpp"

HandleRetWrapper Hash256(const uint8_t *message, const size_t messageSize){
    uint8_t hash[32];
    HandleRetWrapper ret;
    try {
        bls::Util::Hash256(hash, message, messageSize);
    }catch (std::exception &e){
        ret.err = strdup(e.what());
        return ret;
    }
    ret.handle = reinterpret_cast<void *>(BytesWrapperInit(hash,32));
    return ret;
}