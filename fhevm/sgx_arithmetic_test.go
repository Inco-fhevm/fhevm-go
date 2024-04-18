package fhevm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/sgx"
)

func TestSgxAddRun(t *testing.T) {
	SgxLibAdd(t, tfhe.FheUint4)
	SgxLibAdd(t, tfhe.FheUint8)
	SgxLibAdd(t, tfhe.FheUint16)
	SgxLibAdd(t, tfhe.FheUint32)
	SgxLibAdd(t, tfhe.FheUint64)
}

func SgxLibAdd(t *testing.T, fheUintType tfhe.FheUintType) {
	var lhs, rhs uint64
	switch fheUintType {
	case tfhe.FheUint4:
		lhs = 2
		rhs = 1
	case tfhe.FheUint8:
		lhs = 2
		rhs = 1
	case tfhe.FheUint16:
		lhs = 4283
		rhs = 1337
	case tfhe.FheUint32:
		lhs = 1333337
		rhs = 133337
	case tfhe.FheUint64:
		lhs = 13333377777777777
		rhs = 133377777777
	}
	expected := lhs + rhs
	signature := "sgxAdd(uint256,uint256,bytes1)"
	depth := 1
	environment := newTestEVMEnvironment()
	environment.depth = depth
	addr := common.Address{}
	readOnly := false
	lhsCt, err := importSgxCiphertextToEVM(environment, depth, lhs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}
	rhsCt, err := importSgxCiphertextToEVM(environment, depth, rhs, fheUintType)
	if err != nil {
		t.Fatalf(err.Error())
	}

	input := toLibPrecompileInput(signature, false, lhsCt.GetHash(), rhsCt.GetHash())
	out, err := FheLibRun(environment, addr, addr, input, readOnly)
	if err != nil {
		t.Fatalf(err.Error())
	}
	res := getVerifiedCiphertextFromEVM(environment, common.BytesToHash(out))
	if res == nil {
		t.Fatalf("output ciphertext is not found in verifiedCiphertexts")
	}
	decryptedSgxPlaintext, err := sgx.FromTfheCiphertext(res.ciphertext)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if decryptedSgxPlaintext.FheUintType != fheUintType {
		t.Fatalf("incorrect fheUintType, expected=%s, got=%s", fheUintType, decryptedSgxPlaintext.FheUintType)
	}

	var decryptedResult uint64
	switch fheUintType {
	case tfhe.FheUint4:
		decryptedResult = uint64(decryptedSgxPlaintext.AsUint8())
	case tfhe.FheUint8:
		decryptedResult = uint64(decryptedSgxPlaintext.AsUint8())
	case tfhe.FheUint16:
		decryptedResult = uint64(decryptedSgxPlaintext.AsUint16())
	case tfhe.FheUint32:
		decryptedResult = uint64(decryptedSgxPlaintext.AsUint32())
	case tfhe.FheUint64:
		decryptedResult = decryptedSgxPlaintext.AsUint64()
	}

	if decryptedResult != expected {
		t.Fatalf("incorrect result, expected=%d, got=%d", expected, decryptedResult)
	}
}

func toSgxPlaintext(value uint64, typ tfhe.FheUintType) (sgx.SgxPlaintext, error) {
	i := new(big.Int).SetUint64(value)
	return sgx.NewSgxPlaintext(i.Bytes(), typ, common.Address{}), nil
}

func importSgxCiphertextToEVM(environment EVMEnvironment, depth int, value uint64, typ tfhe.FheUintType) (tfhe.TfheCiphertext, error) {
	sgxPlaintext, err := toSgxPlaintext(value, typ)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}
	ct, err := sgx.ToTfheCiphertext(sgxPlaintext)
	if err != nil {
		return tfhe.TfheCiphertext{}, err
	}

	importCiphertextToEVMAtDepth(environment, &ct, depth)
	return ct, nil
}
