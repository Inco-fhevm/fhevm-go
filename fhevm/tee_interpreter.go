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

func doOperationGeneric[T any](
	environment EVMEnvironment, 
	caller common.Address, 
	input []byte, 
	runSpan trace.Span, 
	operator func(uint64, uint64) T,
	op string) ([]byte, error) {
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
	resultBz, err = marshalTfheType(result, lp.FheUintType)
	if err != nil {
		logger.Error(op, "failed", "err", err)
		return nil, err
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

func extract2Operands(op string, environment EVMEnvironment, input []byte, runSpan trace.Span) (*tee.TeePlaintext, *tee.TeePlaintext, *verifiedCiphertext, *verifiedCiphertext,	error) {
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

// marshalTfheType converts a any to a byte slice
func marshalTfheType(value any, typ tfhe.FheUintType) ([]byte, error) {
	switch value := any(value).(type) {
	case uint64:
		switch typ {
		case tfhe.FheUint4:
			resultBz := []byte{byte(value)}
			return resultBz, nil
		case tfhe.FheUint8:
			resultBz := []byte{byte(value)}
			return resultBz, nil
		case tfhe.FheUint16:
			resultBz := make([]byte, 2)
			binary.BigEndian.PutUint16(resultBz, uint16(value))
			return resultBz, nil
		case tfhe.FheUint32:
			resultBz := make([]byte, 4)
			binary.BigEndian.PutUint32(resultBz, uint32(value))
			return resultBz, nil
		case tfhe.FheUint64:
			resultBz := make([]byte, 8)
			binary.BigEndian.PutUint64(resultBz, value)
			return resultBz, nil
		default:
			return nil, 
			fmt.Errorf("unsupported FheUintType: %s", typ)
		}
	case bool:
		resultBz := make([]byte, 1)
		if value {
			resultBz[0] = 1
		} else {
			resultBz[0] = 0
		}
		return resultBz, nil
	default:
		return nil,
		fmt.Errorf("unsupported value type: %s", value)
	}
}
