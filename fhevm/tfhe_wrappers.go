// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package fhevm

/*
#cgo linux CFLAGS: -O3 -I../tfhe-rs/target/release -I../tfhe-rs/target/release/deps
#cgo linux LDFLAGS: -L../tfhe-rs/target/release -l:libtfhe.a -L../tfhe-rs/target/release/deps -l:libtfhe_c_api_dynamic_buffer.a -lm
#cgo darwin CFLAGS: -O3 -I../tfhe-rs/target/release -I../tfhe-rs/target/release/deps
#cgo darwin LDFLAGS: -framework Security -L../tfhe-rs/target/release -ltfhe -L../tfhe-rs/target/release/deps -ltfhe_c_api_dynamic_buffer -lm

#include "tfhe_wrappers.h"

*/
import "C"

import (
	_ "embed"
	"errors"
	"unsafe"
)

func toDynamicBufferView(in []byte) C.DynamicBufferView {
	return C.DynamicBufferView{
		pointer: (*C.uint8_t)(unsafe.Pointer(&in[0])),
		length:  (C.size_t)(len(in)),
	}
}

func serialize(ptr unsafe.Pointer, t FheUintType) ([]byte, error) {
	out := &C.DynamicBuffer{}
	var ret C.int
	switch t {
	case FheUint8:
		ret = C.serialize_fhe_uint8(ptr, out)
	case FheUint16:
		ret = C.serialize_fhe_uint16(ptr, out)
	case FheUint32:
		ret = C.serialize_fhe_uint32(ptr, out)
	case FheUint64:
		ret = C.serialize_fhe_uint64(ptr, out)
	default:
		panic("serialize: unexpected ciphertext type")
	}
	if ret != 0 {
		return nil, errors.New("serialize: failed to serialize a ciphertext")
	}
	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser, nil
}

func serializePublicKey(pks unsafe.Pointer) ([]byte, error) {
	out := &C.DynamicBuffer{}
	var ret C.int
	ret = C.serialize_compact_public_key(pks, out)
	if ret != 0 {
		return nil, errors.New("serialize: failed to serialize public key")
	}
	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser, nil
}

func isValidType(t byte) bool {
	if uint8(t) < uint8(FheUint8) || uint8(t) > uint8(FheUint64) {
		return false
	}
	return true
}

func encryptAndSerializeCompact(value uint64, fheUintType FheUintType) []byte {
	out := &C.DynamicBuffer{}
	switch fheUintType {
	case FheUint8:
		C.public_key_encrypt_and_serialize_fhe_uint8_list(pks, C.uint8_t(value), out)
	case FheUint16:
		C.public_key_encrypt_and_serialize_fhe_uint16_list(pks, C.uint16_t(value), out)
	case FheUint32:
		C.public_key_encrypt_and_serialize_fhe_uint32_list(pks, C.uint32_t(value), out)
	case FheUint64:
		C.public_key_encrypt_and_serialize_fhe_uint64_list(pks, C.uint64_t(value), out)
	}

	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser
}