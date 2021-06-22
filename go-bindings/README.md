# Go bindings

Use the full power and efficiency of the C++ bls library, but in a few lines of go!

## Install

```bash
go get github.com/Sukhavati-Labs/bls-signatures/go-bindings
```

Alternatively, to install from source, run the following, in the project root directory:

```bash
pip3 install .
```

Cmake, a c++ compiler, and a recent version of pip3 (v18) are required for source install.
GMP(speed) and libsodium(secure memory alloc) are optional dependencies.
Public keys are G1Elements, and signatures are G2Elements.

Then, to use:

## Import the library

```go
```

## Creating keys and signatures

```go
```

## Serializing keys and signatures to bytes

```go
```

## Loading keys and signatures from bytes

```go 
```

## Create aggregate signatures

```go
```

## Arbitrary trees of aggregates

```go
```

## Very fast verification with Proof of Possession scheme

```go
```

## HD keys using [EIP-2333](https://github.com/ethereum/EIPs/pull/2333)

```go 
```