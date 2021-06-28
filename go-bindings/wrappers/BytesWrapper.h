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


#ifndef BLS_GO_BINDINGS_BYTES_WRAPPER_H
#define BLS_GO_BINDINGS_BYTES_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef void * BytesWrapper;
BytesWrapper BytesWrapperInit(const uint8_t *buffer, size_t bufferSize);
void BytesWrapperFree(BytesWrapper bytesWrapper);
size_t BytesWrapperSize(BytesWrapper bytesWrapper);
const uint8_t * BytesWrapperBegin(BytesWrapper bytesWrapper);
const uint8_t * BytesWrapperEnd(BytesWrapper bytesWrapper);
uint8_t BytesWrapperIndex(BytesWrapper bytesWrapper,int index);
#ifdef __cplusplus
}
#endif

#endif  // BLS_GO_BINDINGS_BYTES_WRAPPER_H
