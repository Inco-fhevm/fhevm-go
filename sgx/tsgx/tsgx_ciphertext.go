package tsgx

/*
#include "Tsgx_wrappers.h"
*/
import "C"
import (
	"errors"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Represents a TSGX ciphertext type, i.e. its bit capacity.
type SgxUintType uint8

const (
	SgxBool    SgxUintType = 0
	SgxUint4   SgxUintType = 1
	SgxUint8   SgxUintType = 2
	SgxUint16  SgxUintType = 3
	SgxUint32  SgxUintType = 4
	SgxUint64  SgxUintType = 5
	SgxUint128 SgxUintType = 6
	SgxUint160 SgxUintType = 7
)

func (t SgxUintType) String() string {
	switch t {
	case SgxBool:
		return "sgxBool"
	case SgxUint4:
		return "sgxUint4"
	case SgxUint8:
		return "sgxUint8"
	case SgxUint16:
		return "sgxUint16"
	case SgxUint32:
		return "sgxUint32"
	case SgxUint64:
		return "sgxUint64"
	case SgxUint128:
		return "sgxUint128"
	case SgxUint160:
		return "sgxUint160"
	default:
		return "unknownSgxUintType"
	}
}

func IsValidSgxType(t byte) bool {
	if uint8(t) < uint8(SgxBool) || uint8(t) > uint8(SgxUint160) {
		return false
	}
	return true
}

// Represents an expanded TSGX ciphertext.
type TsgxCiphertext struct {
	Serialization []byte
	Hash          *common.Hash
	SgxUintType   SgxUintType
}

func (ct *TsgxCiphertext) Type() SgxUintType {
	return ct.SgxUintType
}
func boolBinaryNotSupportedOp(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
	return nil, errors.New("Bool is not supported")
}

func boolBinaryScalarNotSupportedOp(lhs unsafe.Pointer, rhs C.bool) (unsafe.Pointer, error) {
	return nil, errors.New("Bool is not supported")
}

func sgxUint160BinaryNotSupportedOp(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
	return nil, errors.New("SGXUint160 is not supported")
}

func sgxUint160BinaryScalarNotSupportedOp(lhs unsafe.Pointer, rhs C.U256) (unsafe.Pointer, error) {
	return nil, errors.New("SGXUint160 is not supported")
}

func boolUnaryNotSupportedOp(lhs unsafe.Pointer) (unsafe.Pointer, error) {
	return nil, errors.New("Bool is not supported")
}

// Deserializes a TSGX ciphertext.
func (ct *TsgxCiphertext) Deserialize(in []byte, t SgxUintType) error {
	switch t {
	case SgxBool:
		ptr := C.deserialize_sgx_bool(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("SgxBool ciphertext deserialization failed")
		}
		C.destroy_sgx_bool(ptr)
	case SgxUint4:
		ptr := C.deserialize_sgx_uint4(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("SgxUint4 ciphertext deserialization failed")
		}
		C.destroy_sgx_uint4(ptr)
	case SgxUint8:
		ptr := C.deserialize_sgx_uint8(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("SgxUint8 ciphertext deserialization failed")
		}
		C.destroy_sgx_uint8(ptr)
	case SgxUint16:
		ptr := C.deserialize_sgx_uint16(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("SgxUint16 ciphertext deserialization failed")
		}
		C.destroy_sgx_uint16(ptr)
	case SgxUint32:
		ptr := C.deserialize_sgx_uint32(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("SgxUint32 ciphertext deserialization failed")
		}
		C.destroy_sgx_uint32(ptr)
	case SgxUint64:
		ptr := C.deserialize_sgx_uint64(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("SgxUint64 ciphertext deserialization failed")
		}
		C.destroy_sgx_uint64(ptr)
	case SgxUint160:
		ptr := C.deserialize_sgx_uint160(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("SgxUint160 ciphertext deserialization failed")
		}
		C.destroy_sgx_uint160(ptr)
	default:
		panic("deserialize: unexpected ciphertext type")
	}
	ct.SgxUintType = t
	ct.Serialization = in
	ct.computeHash()
	return nil
}

// Deserializes a compact TSGX ciphetext.
// Note: After the compact TSGX ciphertext has been serialized, subsequent calls to serialize()
// will produce non-compact ciphertext serialziations.
func (ct *TsgxCiphertext) DeserializeCompact(in []byte, t SgxUintType) error {
	switch t {
	case SgxBool:
		ptr := C.deserialize_compact_sgx_bool(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact SgxBool ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_bool(ptr)
		if err != nil {
			return err
		}
	case SgxUint4:
		ptr := C.deserialize_compact_sgx_uint4(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact SgxUint4 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint4(ptr)
		if err != nil {
			return err
		}
	case SgxUint8:
		ptr := C.deserialize_compact_sgx_uint8(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact SgxUint8 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint8(ptr)
		if err != nil {
			return err
		}
	case SgxUint16:
		ptr := C.deserialize_compact_sgx_uint16(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact SgxUint16 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint16(ptr)
		if err != nil {
			return err
		}
	case SgxUint32:
		ptr := C.deserialize_compact_sgx_uint32(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact SgxUint32 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint32(ptr)
		if err != nil {
			return err
		}
	case SgxUint64:
		ptr := C.deserialize_compact_sgx_uint64(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact SgxUint64 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint64(ptr)
		if err != nil {
			return err
		}
	case SgxUint160:
		ptr := C.deserialize_compact_sgx_uint160(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact SgxUint160 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint160(ptr)
		if err != nil {
			return err
		}
	default:
		panic("deserializeCompact: unexpected ciphertext type")
	}
	ct.SgxUintType = t
	ct.computeHash()
	return nil
}

// Encrypts a value as a TSGX ciphertext, using the compact public SGX key.
// The resulting ciphertext is automaticaly expanded.
func (ct *TsgxCiphertext) Encrypt(value big.Int, t SgxUintType) *TsgxCiphertext {
	var ptr unsafe.Pointer
	var err error
	switch t {
	case SgxBool:
		val := false
		if value.Uint64() > 0 {
			val = true
		}
		ptr = C.public_key_encrypt_sgx_bool(pks, C.bool(val))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_bool(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint4:
		ptr = C.public_key_encrypt_sgx_uint4(pks, C.uint8_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint4(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint8:
		ptr = C.public_key_encrypt_sgx_uint8(pks, C.uint8_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint8(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint16:
		ptr = C.public_key_encrypt_sgx_uint16(pks, C.uint16_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint16(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint32:
		ptr = C.public_key_encrypt_sgx_uint32(pks, C.uint32_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint32(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint64:
		ptr = C.public_key_encrypt_sgx_uint64(pks, C.uint64_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint64(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint160:
		input, err := bigIntToU256(&value)
		if err != nil {
			panic(err)
		}
		ptr = C.public_key_encrypt_sgx_uint160(pks, input)
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint160(ptr)
		if err != nil {
			panic(err)
		}
	default:
		panic("encrypt: unexpected ciphertext type")
	}
	ct.SgxUintType = t
	ct.computeHash()
	return ct
}

func (ct *TsgxCiphertext) TrivialEncrypt(value big.Int, t SgxUintType) *TsgxCiphertext {
	var ptr unsafe.Pointer
	var err error
	switch t {
	case SgxBool:
		val := false
		if value.Uint64() > 0 {
			val = true
		}
		ptr = C.trivial_encrypt_sgx_bool(sks, C.bool(val))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_bool(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint4:
		ptr = C.trivial_encrypt_sgx_uint4(sks, C.uint8_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint4(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint8:
		ptr = C.trivial_encrypt_sgx_uint8(sks, C.uint8_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint8(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint16:
		ptr = C.trivial_encrypt_sgx_uint16(sks, C.uint16_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint16(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint32:
		ptr = C.trivial_encrypt_sgx_uint32(sks, C.uint32_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint32(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint64:
		ptr = C.trivial_encrypt_sgx_uint64(sks, C.uint64_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint64(ptr)
		if err != nil {
			panic(err)
		}
	case SgxUint160:
		input, err := bigIntToU256(&value)
		if err != nil {
			panic(err)
		}
		ptr = C.trivial_encrypt_sgx_uint160(sks, *input)
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_sgx_uint160(ptr)
		if err != nil {
			panic(err)
		}
	default:
		panic("trivialEncrypt: unexpected ciphertext type")
	}
	ct.SgxUintType = t
	ct.computeHash()
	return ct
}

func (ct *TsgxCiphertext) Serialize() []byte {
	return ct.Serialization
}

func (ct *TsgxCiphertext) executeUnaryCiphertextOperation(rhs *TsgxCiphertext,
	opBool func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op4 func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op8 func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op16 func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op32 func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op64 func(ct unsafe.Pointer) (unsafe.Pointer, error)) (*TsgxCiphertext, error) {

	res := new(TsgxCiphertext)
	res.SgxUintType = ct.SgxUintType
	res_ser := &C.DynamicBuffer{}
	switch ct.SgxUintType {
	case SgxBool:
		ct_ptr := C.deserialize_sgx_bool(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("Bool unary op deserialization failed")
		}
		res_ptr, err := opBool(ct_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_bool(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("Bool unary op failed")
		}
		ret := C.serialize_sgx_bool(res_ptr, res_ser)
		C.destroy_sgx_bool(res_ptr)
		if ret != 0 {
			return nil, errors.New("Bool unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint4:
		ct_ptr := C.deserialize_sgx_uint4(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("8 bit unary op deserialization failed")
		}
		res_ptr, err := op4(ct_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint4(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit unary op failed")
		}
		ret := C.serialize_sgx_uint4(res_ptr, res_ser)
		C.destroy_sgx_uint4(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint8:
		ct_ptr := C.deserialize_sgx_uint8(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("8 bit unary op deserialization failed")
		}
		res_ptr, err := op8(ct_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint8(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit unary op failed")
		}
		ret := C.serialize_sgx_uint8(res_ptr, res_ser)
		C.destroy_sgx_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint16:
		ct_ptr := C.deserialize_sgx_uint16(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("16 bit unary op deserialization failed")
		}
		res_ptr, err := op16(ct_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint16(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit op failed")
		}
		ret := C.serialize_sgx_uint16(res_ptr, res_ser)
		C.destroy_sgx_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint32:
		ct_ptr := C.deserialize_sgx_uint32(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("32 bit unary op deserialization failed")
		}
		res_ptr, err := op16(ct_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint32(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit op failed")
		}
		ret := C.serialize_sgx_uint32(res_ptr, res_ser)
		C.destroy_sgx_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint64:
		ct_ptr := C.deserialize_sgx_uint64(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("64 bit unary op deserialization failed")
		}
		res_ptr, err := op64(ct_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint64(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit op failed")
		}
		ret := C.serialize_sgx_uint64(res_ptr, res_ser)
		C.destroy_sgx_uint64(res_ptr)
		if ret != 0 {
			return nil, errors.New("64 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("unary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *TsgxCiphertext) executeBinaryCiphertextOperation(rhs *TsgxCiphertext,
	opBool func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op4 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op8 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op16 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op32 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op64 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op160 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	returnBool bool) (*TsgxCiphertext, error) {
	if lhs.SgxUintType != rhs.SgxUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(TsgxCiphertext)
	if returnBool {
		res.SgxUintType = SgxBool
	} else {
		res.SgxUintType = lhs.SgxUintType
	}
	res_ser := &C.DynamicBuffer{}
	switch lhs.SgxUintType {
	case SgxBool:
		lhs_ptr := C.deserialize_sgx_bool(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_bool(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_bool(lhs_ptr)
			return nil, errors.New("bool binary op deserialization failed")
		}
		res_ptr, err := opBool(lhs_ptr, rhs_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_bool(lhs_ptr)
		C.destroy_sgx_bool(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("bool binary op failed")
		}
		ret := C.serialize_sgx_bool(res_ptr, res_ser)
		C.destroy_sgx_bool(res_ptr)
		if ret != 0 {
			return nil, errors.New("bool binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint4:
		lhs_ptr := C.deserialize_sgx_uint4(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("4 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint4(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint4(lhs_ptr)
			return nil, errors.New("4 bit binary op deserialization failed")
		}
		res_ptr, err := op4(lhs_ptr, rhs_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint4(lhs_ptr)
		C.destroy_sgx_uint4(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("4 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint4(res_ptr, res_ser)
			C.destroy_sgx_uint4(res_ptr)
			if ret != 0 {
				return nil, errors.New("4 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint8:
		lhs_ptr := C.deserialize_sgx_uint8(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint8(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint8(lhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		res_ptr, err := op8(lhs_ptr, rhs_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint8(lhs_ptr)
		C.destroy_sgx_uint8(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint8(res_ptr, res_ser)
			C.destroy_sgx_uint8(res_ptr)
			if ret != 0 {
				return nil, errors.New("8 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint16:
		lhs_ptr := C.deserialize_sgx_uint16(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint16(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint16(lhs_ptr)
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		res_ptr, err := op16(lhs_ptr, rhs_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint16(lhs_ptr)
		C.destroy_sgx_uint16(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint16(res_ptr, res_ser)
			C.destroy_sgx_uint16(res_ptr)
			if ret != 0 {
				return nil, errors.New("8 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint32:
		lhs_ptr := C.deserialize_sgx_uint32(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint32(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint32(lhs_ptr)
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		res_ptr, err := op32(lhs_ptr, rhs_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint32(lhs_ptr)
		C.destroy_sgx_uint32(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit binary op failed")
		}

		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint32(res_ptr, res_ser)
			C.destroy_sgx_uint32(res_ptr)
			if ret != 0 {
				return nil, errors.New("32 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint64:
		lhs_ptr := C.deserialize_sgx_uint64(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint64(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint64(lhs_ptr)
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		res_ptr, err := op64(lhs_ptr, rhs_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint64(lhs_ptr)
		C.destroy_sgx_uint64(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint64(res_ptr, res_ser)
			C.destroy_sgx_uint64(res_ptr)
			if ret != 0 {
				return nil, errors.New("64 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint160:
		lhs_ptr := C.deserialize_sgx_uint160(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("160 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint160(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint160(lhs_ptr)
			return nil, errors.New("160 bit binary op deserialization failed")
		}
		res_ptr, err := op160(lhs_ptr, rhs_ptr)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint160(lhs_ptr)
		C.destroy_sgx_uint160(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("160 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint160(res_ptr, res_ser)
			C.destroy_sgx_uint160(res_ptr)
			if ret != 0 {
				return nil, errors.New("160 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("binary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (first *TsgxCiphertext) executeTernaryCiphertextOperation(lhs *TsgxCiphertext, rhs *TsgxCiphertext,
	op4 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op8 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op16 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op32 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op64 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer) (*TsgxCiphertext, error) {
	if lhs.SgxUintType != rhs.SgxUintType {
		return nil, errors.New("ternary operations are only well-defined for identical types")
	}

	res := new(TsgxCiphertext)
	res.SgxUintType = lhs.SgxUintType
	res_ser := &C.DynamicBuffer{}
	switch lhs.SgxUintType {
	case SgxUint4:
		lhs_ptr := C.deserialize_sgx_uint4(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("4 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint4(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint4(lhs_ptr)
			return nil, errors.New("4 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_sgx_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			C.destroy_sgx_uint4(lhs_ptr)
			C.destroy_sgx_uint4(rhs_ptr)
			return nil, errors.New("Bool binary op deserialization failed")
		}
		res_ptr := op4(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_sgx_uint4(lhs_ptr)
		C.destroy_sgx_uint4(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("4 bit binary op failed")
		}
		ret := C.serialize_sgx_uint4(res_ptr, res_ser)
		C.destroy_sgx_uint4(res_ptr)
		if ret != 0 {
			return nil, errors.New("4 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint8:
		lhs_ptr := C.deserialize_sgx_uint8(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint8(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint8(lhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_sgx_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			C.destroy_sgx_uint8(lhs_ptr)
			C.destroy_sgx_uint8(rhs_ptr)
			return nil, errors.New("Bool binary op deserialization failed")
		}
		res_ptr := op8(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_sgx_uint8(lhs_ptr)
		C.destroy_sgx_uint8(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit binary op failed")
		}
		ret := C.serialize_sgx_uint8(res_ptr, res_ser)
		C.destroy_sgx_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint16:
		lhs_ptr := C.deserialize_sgx_uint16(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint16(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint16(lhs_ptr)
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_sgx_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			C.destroy_sgx_uint16(lhs_ptr)
			C.destroy_sgx_uint16(rhs_ptr)
			return nil, errors.New("Bool binary op deserialization failed")
		}
		res_ptr := op16(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_sgx_uint16(lhs_ptr)
		C.destroy_sgx_uint16(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit binary op failed")
		}
		ret := C.serialize_sgx_uint16(res_ptr, res_ser)
		C.destroy_sgx_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint32:
		lhs_ptr := C.deserialize_sgx_uint32(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint32(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint32(lhs_ptr)
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_sgx_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			C.destroy_sgx_uint32(lhs_ptr)
			C.destroy_sgx_uint32(rhs_ptr)
			return nil, errors.New("Bool binary op deserialization failed")
		}
		res_ptr := op32(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_sgx_uint32(lhs_ptr)
		C.destroy_sgx_uint32(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit binary op failed")
		}
		ret := C.serialize_sgx_uint32(res_ptr, res_ser)
		C.destroy_sgx_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint64:
		lhs_ptr := C.deserialize_sgx_uint64(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_sgx_uint64(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			C.destroy_sgx_uint64(lhs_ptr)
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		first_ptr := C.deserialize_sgx_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			C.destroy_sgx_uint64(lhs_ptr)
			C.destroy_sgx_uint64(rhs_ptr)
			return nil, errors.New("Bool binary op deserialization failed")
		}
		res_ptr := op64(first_ptr, lhs_ptr, rhs_ptr)
		C.destroy_sgx_uint64(lhs_ptr)
		C.destroy_sgx_uint64(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit binary op failed")
		}
		ret := C.serialize_sgx_uint64(res_ptr, res_ser)
		C.destroy_sgx_uint64(res_ptr)
		if ret != 0 {
			return nil, errors.New("64 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("ternary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

// Update: Switched 'rhs' from uint64 to *big.Int to enable 160-bit operations (eq,ne).
func (lhs *TsgxCiphertext) executeBinaryScalarOperation(rhs *big.Int,
	opBool func(lhs unsafe.Pointer, rhs C.bool) (unsafe.Pointer, error),
	op4 func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error),
	op8 func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error),
	op16 func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error),
	op32 func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error),
	op64 func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error),
	op160 func(lhs unsafe.Pointer, rhs C.U256) (unsafe.Pointer, error),
	returnBool bool) (*TsgxCiphertext, error) {
	res := new(TsgxCiphertext)
	if returnBool {
		res.SgxUintType = SgxBool
	} else {
		res.SgxUintType = lhs.SgxUintType
	}
	rhs_uint64 := rhs.Uint64()
	res_ser := &C.DynamicBuffer{}
	switch lhs.SgxUintType {
	case SgxBool:
		lhs_ptr := C.deserialize_sgx_bool(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("Bool scalar op deserialization failed")
		}
		scalar := C.bool(rhs_uint64 == 1)
		res_ptr, err := opBool(lhs_ptr, scalar)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_bool(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("Bool scalar op failed")
		}
		ret := C.serialize_sgx_bool(res_ptr, res_ser)
		C.destroy_sgx_bool(res_ptr)
		if ret != 0 {
			return nil, errors.New("Bool scalar op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint4:
		lhs_ptr := C.deserialize_sgx_uint4(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("4 bit scalar op deserialization failed")
		}
		scalar := C.uint8_t(rhs_uint64)
		res_ptr, err := op4(lhs_ptr, scalar)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint4(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("4 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("Bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint4(res_ptr, res_ser)
			C.destroy_sgx_uint4(res_ptr)
			if ret != 0 {
				return nil, errors.New("4 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint8:
		lhs_ptr := C.deserialize_sgx_uint8(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit scalar op deserialization failed")
		}
		scalar := C.uint8_t(rhs_uint64)
		res_ptr, err := op8(lhs_ptr, scalar)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint8(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("Bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint8(res_ptr, res_ser)
			C.destroy_sgx_uint8(res_ptr)
			if ret != 0 {
				return nil, errors.New("8 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint16:
		lhs_ptr := C.deserialize_sgx_uint16(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit scalar op deserialization failed")
		}
		scalar := C.uint16_t(rhs_uint64)
		res_ptr, err := op16(lhs_ptr, scalar)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint16(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("Bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint16(res_ptr, res_ser)
			C.destroy_sgx_uint16(res_ptr)
			if ret != 0 {
				return nil, errors.New("16 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint32:
		lhs_ptr := C.deserialize_sgx_uint32(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit scalar op deserialization failed")
		}
		scalar := C.uint32_t(rhs_uint64)
		res_ptr, err := op32(lhs_ptr, scalar)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint32(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("Bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint32(res_ptr, res_ser)
			C.destroy_sgx_uint32(res_ptr)
			if ret != 0 {
				return nil, errors.New("32 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint64:
		lhs_ptr := C.deserialize_sgx_uint64(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit scalar op deserialization failed")
		}
		scalar := C.uint64_t(rhs_uint64)
		res_ptr, err := op64(lhs_ptr, scalar)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint64(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("Bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint64(res_ptr, res_ser)
			C.destroy_sgx_uint64(res_ptr)
			if ret != 0 {
				return nil, errors.New("64 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case SgxUint160:
		lhs_ptr := C.deserialize_sgx_uint160(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("160 bit scalar op deserialization failed")
		}

		scalar, err := bigIntToU256(rhs)

		res_ptr, err := op160(lhs_ptr, *scalar)
		if err != nil {
			return nil, err
		}
		C.destroy_sgx_uint160(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("160 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_sgx_bool(res_ptr, res_ser)
			C.destroy_sgx_bool(res_ptr)
			if ret != 0 {
				return nil, errors.New("Bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_sgx_uint160(res_ptr, res_ser)
			C.destroy_sgx_uint160(res_ptr)
			if ret != 0 {
				return nil, errors.New("160 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)

	default:
		panic("scalar op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *TsgxCiphertext) Add(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) ScalarAdd(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_add_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_add_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_add_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_add_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_add_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Sub(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) ScalarSub(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_sub_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_sub_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_sub_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_sub_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_sub_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Mul(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) ScalarMul(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_mul_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_mul_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_mul_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_mul_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_mul_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) ScalarDiv(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_div_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_div_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_div_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_div_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_div_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) ScalarRem(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_rem_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_rem_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_rem_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_rem_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_rem_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Bitand(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_sgx_bool(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Bitor(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_sgx_bool(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Bitxor(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_sgx_bool(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Shl(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) ScalarShl(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_shl_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_shl_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_shl_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_shl_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_shl_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Shr(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp,
		false)
}

func (lhs *TsgxCiphertext) ScalarShr(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_shr_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_shr_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_shr_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_shr_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_shr_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Eq(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_sgx_uint64(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_sgx_uint160(lhs, rhs, sks), nil
		},
		true)
}

func (lhs *TsgxCiphertext) ScalarEq(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_eq_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_eq_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_eq_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_eq_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_eq_sgx_uint64(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.U256) (unsafe.Pointer, error) {
			return C.scalar_eq_sgx_uint160(lhs, rhs, sks), nil
		},
		true)
}

func (lhs *TsgxCiphertext) Ne(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_sgx_uint64(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_sgx_uint160(lhs, rhs, sks), nil
		},
		true)
}

func (lhs *TsgxCiphertext) ScalarNe(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_ne_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_ne_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_ne_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_ne_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_ne_sgx_uint64(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.U256) (unsafe.Pointer, error) {
			return C.scalar_ne_sgx_uint160(lhs, rhs, sks), nil
		},
		true)
}

func (lhs *TsgxCiphertext) Ge(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp,
		true)
}

func (lhs *TsgxCiphertext) ScalarGe(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_ge_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_ge_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_ge_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_ge_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_ge_sgx_uint64(lhs, rhs, sks), nil
		}, sgxUint160BinaryScalarNotSupportedOp,
		true)
}

func (lhs *TsgxCiphertext) Gt(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp,
		true)
}

func (lhs *TsgxCiphertext) ScalarGt(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_gt_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_gt_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_gt_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_gt_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_gt_sgx_uint64(lhs, rhs, sks), nil
		}, sgxUint160BinaryScalarNotSupportedOp,
		true)
}

func (lhs *TsgxCiphertext) Le(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp,
		true)
}

func (lhs *TsgxCiphertext) ScalarLe(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_le_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_le_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_le_sgx_uint16(lhs, rhs, sks), nil

		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_le_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_le_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp,
		true)
}

func (lhs *TsgxCiphertext) Lt(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp,
		true)
}

func (lhs *TsgxCiphertext) ScalarLt(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_lt_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_lt_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_lt_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_lt_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_lt_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp,
		true)
}

func (lhs *TsgxCiphertext) Min(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) ScalarMin(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_min_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_min_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_min_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_min_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_min_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Max(rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) ScalarMax(rhs *big.Int) (*TsgxCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_max_sgx_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_max_sgx_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_max_sgx_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_max_sgx_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_max_sgx_uint64(lhs, rhs, sks), nil
		},
		sgxUint160BinaryScalarNotSupportedOp, false)
}

func (lhs *TsgxCiphertext) Neg() (*TsgxCiphertext, error) {
	return lhs.executeUnaryCiphertextOperation(lhs,
		boolUnaryNotSupportedOp,
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_sgx_uint4(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_sgx_uint8(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_sgx_uint16(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_sgx_uint32(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_sgx_uint64(lhs, sks), nil
		})
}

func (lhs *TsgxCiphertext) Not() (*TsgxCiphertext, error) {
	return lhs.executeUnaryCiphertextOperation(lhs,
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_sgx_bool(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_sgx_uint4(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_sgx_uint8(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_sgx_uint16(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_sgx_uint32(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_sgx_uint64(lhs, sks), nil
		})
}

func (condition *TsgxCiphertext) IfThenElse(lhs *TsgxCiphertext, rhs *TsgxCiphertext) (*TsgxCiphertext, error) {
	return condition.executeTernaryCiphertextOperation(lhs, rhs,
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_sgx_uint4(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_sgx_uint8(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_sgx_uint16(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_sgx_uint32(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_sgx_uint64(condition, lhs, rhs, sks)
		})
}

func (ct *TsgxCiphertext) CastTo(castToType SgxUintType) (*TsgxCiphertext, error) {
	if ct.SgxUintType == castToType {
		return nil, errors.New("casting to same type is not supported")
	}

	res := new(TsgxCiphertext)
	res.SgxUintType = castToType

	switch ct.SgxUintType {
	case SgxBool:
		switch castToType {
		case SgxUint4:
			from_ptr := C.deserialize_sgx_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxBool ciphertext")
			}
			to_ptr := C.cast_bool_4(from_ptr, sks)
			C.destroy_sgx_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxBool to SgxUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint8:
			from_ptr := C.deserialize_sgx_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxBool ciphertext")
			}
			to_ptr := C.cast_bool_8(from_ptr, sks)
			C.destroy_sgx_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxBool to SgxUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint16:
			from_ptr := C.deserialize_sgx_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxBool ciphertext")
			}
			to_ptr := C.cast_bool_16(from_ptr, sks)
			C.destroy_sgx_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxBool to SgxUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint32:
			from_ptr := C.deserialize_sgx_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxBool ciphertext")
			}
			to_ptr := C.cast_bool_32(from_ptr, sks)
			C.destroy_sgx_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxBool to SgxUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint64:
			from_ptr := C.deserialize_sgx_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxBool ciphertext")
			}
			to_ptr := C.cast_bool_64(from_ptr, sks)
			C.destroy_sgx_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxBool to SgxUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case SgxUint4:
		switch castToType {
		case SgxUint8:
			from_ptr := C.deserialize_sgx_uint4(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint4 ciphertext")
			}
			to_ptr := C.cast_4_8(from_ptr, sks)
			C.destroy_sgx_uint4(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint4 to SgxUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint16:
			from_ptr := C.deserialize_sgx_uint4(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint4 ciphertext")
			}
			to_ptr := C.cast_4_16(from_ptr, sks)
			C.destroy_sgx_uint4(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint4 to SgxUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint32:
			from_ptr := C.deserialize_sgx_uint4(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint4 ciphertext")
			}
			to_ptr := C.cast_4_32(from_ptr, sks)
			C.destroy_sgx_uint4(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint4 to SgxUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint64:
			from_ptr := C.deserialize_sgx_uint4(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint4 ciphertext")
			}
			to_ptr := C.cast_4_64(from_ptr, sks)
			C.destroy_sgx_uint4(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint4 to SgxUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case SgxUint8:
		switch castToType {
		case SgxUint4:
			from_ptr := C.deserialize_sgx_uint8(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint8 ciphertext")
			}
			to_ptr := C.cast_8_4(from_ptr, sks)
			C.destroy_sgx_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint8 to SgxUint4")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint16:
			from_ptr := C.deserialize_sgx_uint8(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint8 ciphertext")
			}
			to_ptr := C.cast_8_16(from_ptr, sks)
			C.destroy_sgx_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint8 to SgxUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint32:
			from_ptr := C.deserialize_sgx_uint8(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint8 ciphertext")
			}
			to_ptr := C.cast_8_32(from_ptr, sks)
			C.destroy_sgx_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint8 to SgxUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint64:
			from_ptr := C.deserialize_sgx_uint8(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint8 ciphertext")
			}
			to_ptr := C.cast_8_64(from_ptr, sks)
			C.destroy_sgx_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint8 to SgxUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case SgxUint16:
		switch castToType {
		case SgxUint4:
			from_ptr := C.deserialize_sgx_uint16(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint16 ciphertext")
			}
			to_ptr := C.cast_16_4(from_ptr, sks)
			C.destroy_sgx_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint16 to SgxUint4")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint8:
			from_ptr := C.deserialize_sgx_uint16(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint16 ciphertext")
			}
			to_ptr := C.cast_16_8(from_ptr, sks)
			C.destroy_sgx_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint16 to SgxUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint32:
			from_ptr := C.deserialize_sgx_uint16(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint16 ciphertext")
			}
			to_ptr := C.cast_16_32(from_ptr, sks)
			C.destroy_sgx_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint16 to SgxUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint64:
			from_ptr := C.deserialize_sgx_uint16(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint16 ciphertext")
			}
			to_ptr := C.cast_16_64(from_ptr, sks)
			C.destroy_sgx_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint16 to SgxUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case SgxUint32:
		switch castToType {
		case SgxUint4:
			from_ptr := C.deserialize_sgx_uint32(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint32 ciphertext")
			}
			to_ptr := C.cast_32_4(from_ptr, sks)
			C.destroy_sgx_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint32 to SgxUint4")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint8:
			from_ptr := C.deserialize_sgx_uint32(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint32 ciphertext")
			}
			to_ptr := C.cast_32_8(from_ptr, sks)
			C.destroy_sgx_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint32 to SgxUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint16:
			from_ptr := C.deserialize_sgx_uint32(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint32 ciphertext")
			}
			to_ptr := C.cast_32_16(from_ptr, sks)
			C.destroy_sgx_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint32 to SgxUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint64:
			from_ptr := C.deserialize_sgx_uint32(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint32 ciphertext")
			}
			to_ptr := C.cast_32_64(from_ptr, sks)
			C.destroy_sgx_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint32 to SgxUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case SgxUint64:
		switch castToType {
		case SgxUint4:
			from_ptr := C.deserialize_sgx_uint64(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint64 ciphertext")
			}
			to_ptr := C.cast_64_4(from_ptr, sks)
			C.destroy_sgx_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint64 to SgxUint4")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint8:
			from_ptr := C.deserialize_sgx_uint64(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint64 ciphertext")
			}
			to_ptr := C.cast_64_8(from_ptr, sks)
			C.destroy_sgx_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint64 to SgxUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint16:
			from_ptr := C.deserialize_sgx_uint64(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint64 ciphertext")
			}
			to_ptr := C.cast_64_16(from_ptr, sks)
			C.destroy_sgx_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint64 to SgxUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case SgxUint32:
			from_ptr := C.deserialize_sgx_uint64(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize SgxUint64 ciphertext")
			}
			to_ptr := C.cast_64_32(from_ptr, sks)
			C.destroy_sgx_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast SgxUint64 to SgxUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_sgx_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	}
	res.computeHash()
	return res, nil
}

func (ct *TsgxCiphertext) Decrypt() (big.Int, error) {
	if cks == nil {
		return *new(big.Int).SetUint64(0), errors.New("cks is not initialized")
	}
	var value uint64
	var ret C.int
	switch ct.SgxUintType {
	case SgxBool:
		ptr := C.deserialize_sgx_bool(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize SgxBool")
		}
		var result C.bool
		ret = C.decrypt_sgx_bool(cks, ptr, &result)
		C.destroy_sgx_bool(ptr)
		if result {
			value = 1
		} else {
			value = 0
		}
	case SgxUint4:
		ptr := C.deserialize_sgx_uint4(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize SgxUint4")
		}
		var result C.uint8_t
		ret = C.decrypt_sgx_uint4(cks, ptr, &result)
		C.destroy_sgx_uint4(ptr)
		value = uint64(result)
	case SgxUint8:
		ptr := C.deserialize_sgx_uint8(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize SgxUint8")
		}
		var result C.uint8_t
		ret = C.decrypt_sgx_uint8(cks, ptr, &result)
		C.destroy_sgx_uint8(ptr)
		value = uint64(result)
	case SgxUint16:
		ptr := C.deserialize_sgx_uint16(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize SgxUint16")
		}
		var result C.uint16_t
		ret = C.decrypt_sgx_uint16(cks, ptr, &result)
		C.destroy_sgx_uint16(ptr)
		value = uint64(result)
	case SgxUint32:
		ptr := C.deserialize_sgx_uint32(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize SgxUint32")
		}
		var result C.uint32_t
		ret = C.decrypt_sgx_uint32(cks, ptr, &result)
		C.destroy_sgx_uint32(ptr)
		value = uint64(result)
	case SgxUint64:
		ptr := C.deserialize_sgx_uint64(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize SgxUint64")
		}
		var result C.uint64_t
		ret = C.decrypt_sgx_uint64(cks, ptr, &result)
		C.destroy_sgx_uint64(ptr)
		value = uint64(result)
	case SgxUint160:
		ptr := C.deserialize_sgx_uint160(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize SgxUint160")
		}
		var result C.U256
		ret = C.decrypt_sgx_uint160(cks, ptr, &result)
		if ret != 0 {
			return *new(big.Int).SetUint64(0), errors.New("failed to decrypt SgxUint160")
		}
		C.destroy_sgx_uint160(ptr)
		resultBigInt := *u256ToBigInt(result)
		return resultBigInt, nil
	default:
		panic("decrypt: unexpected ciphertext type")
	}
	if ret != 0 {
		return *new(big.Int).SetUint64(0), errors.New("decrypt failed")
	}
	return *new(big.Int).SetUint64(value), nil
}

func (ct *TsgxCiphertext) computeHash() {
	hash := common.BytesToHash(crypto.Keccak256(ct.Serialization))
	ct.Hash = &hash
}

func (ct *TsgxCiphertext) GetHash() common.Hash {
	if ct.Hash != nil {
		return *ct.Hash
	}
	ct.computeHash()
	return *ct.Hash
}
