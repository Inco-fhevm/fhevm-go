package sgx

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"go.opentelemetry.io/otel/trace"
)

// A method available in the fhelib precompile that can run and estimate gas
type FheLibMethod struct {
	// name of the fhelib function
	name string
	// types of the arguments that the fhelib function take. format is "(type1,type2...)" (e.g "(uint256,bytes1)")
	argTypes            string
	requiredGasFunction func(environment EVMEnvironment, input []byte) uint64
	runFunction         func(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error)
}

func (fheLibMethod *FheLibMethod) Name() string {
	return fheLibMethod.name
}

func makeKeccakSignature(input string) uint32 {
	return binary.BigEndian.Uint32(crypto.Keccak256([]byte(input))[0:4])
}

// Return the computed signature by concatenating the name and the arg types of the method
func (fheLibMethod *FheLibMethod) Signature() uint32 {
	return makeKeccakSignature(fheLibMethod.name + fheLibMethod.argTypes)
}

func (fheLibMethod *FheLibMethod) RequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return fheLibMethod.requiredGasFunction(environment, input)
}

func (fheLibMethod *FheLibMethod) Run(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	return fheLibMethod.runFunction(environment, caller, addr, input, readOnly, runSpan)
}

// Mapping between function signatures and the functions to call
var signatureToFheLibMethod = map[uint32]*FheLibMethod{}

func GetFheLibMethod(signature uint32) (fheLibMethod *FheLibMethod, found bool) {
	fheLibMethod, found = signatureToFheLibMethod[signature]
	return
}

// All methods available in the fhelib precompile
var sgxlibMethods = []*FheLibMethod{
	// SGX operations
	{
		name:                "sgxAdd",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: sgxAddSubRequiredGas,
		runFunction:         sgxAddRun,
	},
	{
		name:                "sgxSub",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: sgxAddSubRequiredGas,
		runFunction:         sgxSubRun,
	},
	{
		name:                "sgxMul",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: sgxMulRequiredGas,
		runFunction:         sgxMulRun,
	},
	{
		name:                "sgxDiv",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: sgxDivRequiredGas,
		runFunction:         sgxDivRun,
	},
}

func init() {
	// create the mapping for every available fhelib method
	for _, method := range sgxlibMethods {
		signatureToFheLibMethod[method.Signature()] = method
	}

}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

// apply padding to slice to the multiple of 32
func padArrayTo32Multiple(input []byte) []byte {
	modRes := len(input) % 32
	if modRes > 0 {
		padding := 32 - modRes
		for padding > 0 {
			padding--
			input = append(input, 0x0)
		}
	}
	return input
}

// Return a memory with a layout that matches the `bytes` EVM type, namely:
//   - 32 byte integer in big-endian order as length
//   - the actual bytes in the `bytes` value
//   - add zero byte padding until nearest multiple of 32
func toEVMBytes(input []byte) []byte {
	arrLen := uint64(len(input))
	lenBytes32 := uint256.NewInt(arrLen).Bytes32()
	ret := make([]byte, 0, arrLen+32)
	ret = append(ret, lenBytes32[:]...)
	ret = append(ret, input...)
	return ret
}

func get2VerifiedOperands(environment EVMEnvironment, input []byte) (lhs *verifiedCiphertext, rhs *verifiedCiphertext, err error) {
	if len(input) != 65 {
		return nil, nil, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	lhs = getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	rhs = getVerifiedCiphertext(environment, common.BytesToHash(input[32:64]))
	if rhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	err = nil
	return
}

func isScalarOp(input []byte) (bool, error) {
	if len(input) != 65 {
		return false, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	isScalar := (input[64] == 1)
	return isScalar, nil
}

func get3VerifiedOperands(environment EVMEnvironment, input []byte) (first *verifiedCiphertext, second *verifiedCiphertext, third *verifiedCiphertext, err error) {
	if len(input) != 96 {
		return nil, nil, nil, errors.New("input needs to contain three 256-bit sized values")
	}
	first = getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if first == nil {
		return nil, nil, nil, errors.New("unverified ciphertext handle")
	}
	second = getVerifiedCiphertext(environment, common.BytesToHash(input[32:64]))
	if second == nil {
		return nil, nil, nil, errors.New("unverified ciphertext handle")
	}
	third = getVerifiedCiphertext(environment, common.BytesToHash(input[64:96]))
	if third == nil {
		return nil, nil, nil, errors.New("unverified ciphertext handle")
	}
	err = nil
	return
}

func getScalarOperands(environment EVMEnvironment, input []byte) (lhs *verifiedCiphertext, rhs *big.Int, err error) {
	if len(input) != 65 {
		return nil, nil, errors.New("input needs to contain two 256-bit sized values and 1 8-bit value")
	}
	lhs = getVerifiedCiphertext(environment, common.BytesToHash(input[0:32]))
	if lhs == nil {
		return nil, nil, errors.New("unverified ciphertext handle")
	}
	rhs = &big.Int{}
	rhs.SetBytes(input[32:64])
	return
}
