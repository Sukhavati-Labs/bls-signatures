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


#ifndef BLS_GO_BINDINGS_SCHEME_MPL_WRAPPER_H
#define BLS_GO_BINDINGS_SCHEME_MPL_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include "PrivateKeyWrapper.h"

typedef void * BasicSchemeMPLWrapper;
BasicSchemeMPLWrapper BasicSchemeMPLWrapperInit();

PrivateKeyWrapper BasicSchemeMPLWrapperGenKey(
    BasicSchemeMPLWrapper basicScheme,
    const uint8_t * seed,size_t size);

typedef void * AugSchemeMPLWrapper;
AugSchemeMPLWrapper AugSchemeMPLWrapperInit();

#endif  // BLS_GO_BINDINGS_SCHEME_MPL_WRAPPER_H
