package fhevm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"github.com/zama-ai/fhevm-go/tee"
	"go.opentelemetry.io/otel/trace"
)

func doOperationGeneric[T any](op string, environment EVMEnvironment, caller common.Address, input []byte, runSpan trace.Span, operator func(uint64, uint64) T) ([]byte, error) {
	logger := environment.GetLogger()

	lp, rp, lhs, rhs, err := extract2Operands(op, environment, input, runSpan)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return importRandomCiphertext(environment, lhs.fheUintType()), nil
	}

	// TODO ref: https://github.com/Inco-fhevm/inco-monorepo/issues/6
	if lp.FheUintType == tfhe.FheUint128 || lp.FheUintType == tfhe.FheUint160 {
		panic("TODO implement me")
	}

	// Using math/big here to make code more readable.
	// A more efficient way would be to use binary.BigEndian.UintXX().
	// However, that would require a switch case. We prefer for now to use
	// big.Int as a one-liner that can handle variable-length bytes.
	//
	// Note that we do arithmetic operations on uint64, then we convert the
	// result back to the FheUintType.
	l := big.NewInt(0).SetBytes(lp.Value).Uint64()
	r := big.NewInt(0).SetBytes(rp.Value).Uint64()

	result := operator(l, r)
	var resultBz []byte
	// Type switch to handle different types of T.
	switch res := any(result).(type) {
	case uint64:
		var err error
		resultBz, err = marshalUint(res, lp.FheUintType) // Marshal uint64 result.
		if err != nil {
			return nil, err
		}
	case bool:
		var err error
		resultBz, err = marshalBool(res) // Marshal bool result.
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported result type")
	}
	teePlaintext := tee.NewTeePlaintext(resultBz, lp.FheUintType, caller)

	resultCt, err := tee.Encrypt(teePlaintext)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
	}
	importCiphertext(environment, &resultCt)

	resultHash := resultCt.GetHash()
	logger.Info(fmt.Sprintf("%s success", op), "lhs", lhs.hash().Hex(), "rhs", rhs.hash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func extract2Operands(op string, environment EVMEnvironment, input []byte, runSpan trace.Span) (*tee.TeePlaintext, *tee.TeePlaintext, *verifiedCiphertext, *verifiedCiphertext, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	lhs, rhs, err := get2VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
	if err != nil {
		logger.Error(fmt.Sprintf("%s inputs not verified", op), "err", err, "input", hex.EncodeToString(input))
		return nil, nil, nil, nil, err
	}
	if lhs.fheUintType() != rhs.fheUintType() {
		logger.Error(fmt.Sprintf("%s operand type mismatch", op), "lhs", lhs.fheUintType(), "rhs", rhs.fheUintType())
		return nil, nil, nil, nil, errors.New("operand type mismatch")
	}

	lp, err := tee.Decrypt(lhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, lhs, rhs, err
	}

	rp, err := tee.Decrypt(rhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, lhs, rhs, err
	}

	return &lp, &rp, lhs, rhs, nil
}

func extract3Operands(op string, environment EVMEnvironment, input []byte, runSpan trace.Span) (*tee.TeePlaintext, *tee.TeePlaintext, *tee.TeePlaintext, *verifiedCiphertext, *verifiedCiphertext, *verifiedCiphertext, error) {
	input = input[:minInt(96, len(input))]

	logger := environment.GetLogger()

	fhs, shs, ths, err := get3VerifiedOperands(environment, input)
	otelDescribeOperands(runSpan, encryptedOperand(*fhs), encryptedOperand(*shs), encryptedOperand(*ths))
	if err != nil {
		logger.Error(fmt.Sprintf("%s inputs not verified", op), "err", err, "input", hex.EncodeToString(input))
		return nil, nil, nil, nil, nil, nil, err
	}
	if shs.fheUintType() != ths.fheUintType() {
		logger.Error(fmt.Sprintf("%s operand type mismatch", op), "shs", shs.fheUintType(), "ths", ths.fheUintType())
		return nil, nil, nil, nil, nil, nil, errors.New("operand type mismatch")
	}

	fp, err := tee.Decrypt(fhs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, nil, fhs, shs, ths, err
	}

	sp, err := tee.Decrypt(shs.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, nil, fhs, shs, ths, err
	}

	tp, err := tee.Decrypt(ths.ciphertext)
	if err != nil {
		logger.Error(fmt.Sprintf("%s failed", op), "err", err)
		return nil, nil, nil, fhs, shs, ths, err
	}

	return &fp, &sp, &tp, fhs, shs, ths, nil
}

// marshalUint converts a uint64 to a byte slice whose length is based on the FheUintType.
func marshalUint(value uint64, typ tfhe.FheUintType) ([]byte, error) {
	var resultBz []byte

	switch typ {
	case tfhe.FheUint4:
		resultBz = []byte{byte(value)}
	case tfhe.FheUint8:
		resultBz = []byte{byte(value)}
	case tfhe.FheUint16:
		resultBz = make([]byte, 2)
		binary.BigEndian.PutUint16(resultBz, uint16(value))
	case tfhe.FheUint32:
		resultBz = make([]byte, 4)
		binary.BigEndian.PutUint32(resultBz, uint32(value))
	case tfhe.FheUint64:
		resultBz = make([]byte, 8)
		binary.BigEndian.PutUint64(resultBz, value)
	default:
		return nil, fmt.Errorf("unsupported FheUintType: %s", typ)
	}

	return resultBz, nil
}

// marshalBool converts a bool to a byte slice
func marshalBool(value bool) ([]byte, error) {
	var resultBz = make([]byte, 1)
	if value {
		resultBz[0] = 1
	} else {
		resultBz[0] = 0
	}

	return resultBz, nil
}
