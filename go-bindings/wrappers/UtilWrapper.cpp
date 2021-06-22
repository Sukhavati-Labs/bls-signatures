#include "UtilWrapper.h"
#include "relic.h"
#include "../../src/util.hpp"

BytesWrapper BytesWrapperInit(const uint8_t * buffer ,size_t bufferSize){
   bls::Bytes * bytesWrapper =  new bls::Bytes(buffer,bufferSize);
   return (void *)bytesWrapper;
}

void BytesWrapperFree(BytesWrapper bytesWrapper){
   bls::Bytes *b = (bls::Bytes *) bytesWrapper;
   delete b;
}

size_t BytesWrapperSize(BytesWrapper bytesWrapper){
    bls::Bytes *b = (bls::Bytes *) bytesWrapper;
    return b->size();
}

const uint8_t * BytesWrapperBegin(BytesWrapper bytesWrapper){
    bls::Bytes *b = (bls::Bytes *) bytesWrapper;
    return b->begin();
}

uint8_t BytesWrapperIndex(BytesWrapper bytesWrapper,int index){
    bls::Bytes *b = (bls::Bytes *) bytesWrapper;
    uint8_t c = (*b)[index];
    return c;
}