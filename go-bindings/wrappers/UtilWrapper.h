#ifndef BLS_GO_BINDINGS_UTIL_WRAPPER_H
#define BLS_GO_BINDINGS_UTIL_WRAPPER_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef void *BytesWrapper;
BytesWrapper BytesWrapperInit(const uint8_t *buffer, size_t bufferSize);
void BytesWrapperFree(BytesWrapper bytesWrapper);
size_t BytesWrapperSize(BytesWrapper bytesWrapper);
const uint8_t * BytesWrapperBegin(BytesWrapper bytesWrapper);
uint8_t BytesWrapperIndex(BytesWrapper bytesWrapper,int index);
#ifdef __cplusplus
}
#endif

#endif //BLS_GO_BINDINGS_UTIL_WRAPPER_H


