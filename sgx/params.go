package sgx

import "github.com/zama-ai/fhevm-go/sgx/tsgx"

// This file contains default gas costs of fhEVM-related operations.
// Users can change the values based on specific requirements in their blockchain.

// Base gas costs of existing EVM operations. Used for setting gas costs relative to them.
// These constants are used just for readability.
const EvmNetSstoreInitGas uint64 = 20000
const AdjustFHEGas uint64 = 10000
const ColdSloadCostEIP2929 uint64 = 2100

const GetNonExistentCiphertextGas uint64 = 1000

var (
	// TODO: The values here are chosen somewhat arbitrarily (at least the 8 bit ones). Also, we don't
	// take into account whether a ciphertext existed (either "current" or "original") for the given handle.
	// Finally, costs are likely to change in the future.
	SgxUint8ProtectedStorageSstoreGas  uint64 = EvmNetSstoreInitGas + 2000
	SgxUint16ProtectedStorageSstoreGas uint64 = SgxUint8ProtectedStorageSstoreGas * 2
	SgxUint32ProtectedStorageSstoreGas uint64 = SgxUint16ProtectedStorageSstoreGas * 2

	// TODO: We don't take whether the slot is cold or warm into consideration.
	SgxUint8ProtectedStorageSloadGas  uint64 = ColdSloadCostEIP2929 + 200
	SgxUint16ProtectedStorageSloadGas uint64 = SgxUint8ProtectedStorageSloadGas * 2
	SgxUint32ProtectedStorageSloadGas uint64 = SgxUint16ProtectedStorageSloadGas * 2
)

func DefaultSgxvmParams() SgxParams {
	return SgxParams{
		GasCosts:                        DefaultGasCosts(),
		DisableDecryptionsInTransaction: false,
	}
}

type SgxParams struct {
	GasCosts                        GasCosts
	DisableDecryptionsInTransaction bool
}

type GasCosts struct {
	SgxCast           uint64
	SgxPubKey         uint64
	SgxAddSub         map[tsgx.SgxUintType]uint64
	SgxDecrypt        map[tsgx.SgxUintType]uint64
	SgxBitwiseOp      map[tsgx.SgxUintType]uint64
	SgxMul            map[tsgx.SgxUintType]uint64
	SgxScalarMul      map[tsgx.SgxUintType]uint64
	SgxScalarDiv      map[tsgx.SgxUintType]uint64
	SgxScalarRem      map[tsgx.SgxUintType]uint64
	SgxShift          map[tsgx.SgxUintType]uint64
	SgxScalarShift    map[tsgx.SgxUintType]uint64
	SgxEq             map[tsgx.SgxUintType]uint64
	SgxLe             map[tsgx.SgxUintType]uint64
	SgxMinMax         map[tsgx.SgxUintType]uint64
	SgxScalarMinMax   map[tsgx.SgxUintType]uint64
	SgxNot            map[tsgx.SgxUintType]uint64
	SgxNeg            map[tsgx.SgxUintType]uint64
	SgxReencrypt      map[tsgx.SgxUintType]uint64
	SgxTrivialEncrypt map[tsgx.SgxUintType]uint64
	SgxRand           map[tsgx.SgxUintType]uint64
	SgxIfThenElse     map[tsgx.SgxUintType]uint64
	SgxVerify         map[tsgx.SgxUintType]uint64
	SgxGetCiphertext  map[tsgx.SgxUintType]uint64
}

func DefaultGasCosts() GasCosts {
	return GasCosts{
		SgxAddSub: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  55000 + AdjustFHEGas,
			tsgx.SgxUint8:  84000 + AdjustFHEGas,
			tsgx.SgxUint16: 123000 + AdjustFHEGas,
			tsgx.SgxUint32: 152000 + AdjustFHEGas,
			tsgx.SgxUint64: 178000 + AdjustFHEGas,
		},
		SgxDecrypt: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  500000,
			tsgx.SgxUint8:  500000,
			tsgx.SgxUint16: 500000,
			tsgx.SgxUint32: 500000,
			tsgx.SgxUint64: 500000,
		},
		SgxBitwiseOp: map[tsgx.SgxUintType]uint64{
			tsgx.SgxBool:   16000 + AdjustFHEGas,
			tsgx.SgxUint4:  22000 + AdjustFHEGas,
			tsgx.SgxUint8:  24000 + AdjustFHEGas,
			tsgx.SgxUint16: 24000 + AdjustFHEGas,
			tsgx.SgxUint32: 25000 + AdjustFHEGas,
			tsgx.SgxUint64: 28000 + AdjustFHEGas,
		},
		SgxMul: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  140000 + AdjustFHEGas,
			tsgx.SgxUint8:  187000 + AdjustFHEGas,
			tsgx.SgxUint16: 252000 + AdjustFHEGas,
			tsgx.SgxUint32: 349000 + AdjustFHEGas,
			tsgx.SgxUint64: 631000 + AdjustFHEGas,
		},
		SgxScalarMul: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  78000 + AdjustFHEGas,
			tsgx.SgxUint8:  149000 + AdjustFHEGas,
			tsgx.SgxUint16: 198000 + AdjustFHEGas,
			tsgx.SgxUint32: 254000 + AdjustFHEGas,
			tsgx.SgxUint64: 346000 + AdjustFHEGas,
		},
		SgxScalarDiv: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  129000 + AdjustFHEGas,
			tsgx.SgxUint8:  228000 + AdjustFHEGas,
			tsgx.SgxUint16: 304000 + AdjustFHEGas,
			tsgx.SgxUint32: 388000 + AdjustFHEGas,
			tsgx.SgxUint64: 574000 + AdjustFHEGas,
		},
		SgxScalarRem: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  276000 + AdjustFHEGas,
			tsgx.SgxUint8:  450000 + AdjustFHEGas,
			tsgx.SgxUint16: 612000 + AdjustFHEGas,
			tsgx.SgxUint32: 795000 + AdjustFHEGas,
			tsgx.SgxUint64: 1095000 + AdjustFHEGas,
		},
		SgxShift: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  106000 + AdjustFHEGas,
			tsgx.SgxUint8:  123000 + AdjustFHEGas,
			tsgx.SgxUint16: 143000 + AdjustFHEGas,
			tsgx.SgxUint32: 173000 + AdjustFHEGas,
			tsgx.SgxUint64: 217000 + AdjustFHEGas,
		},
		SgxScalarShift: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  25000 + AdjustFHEGas,
			tsgx.SgxUint8:  25000 + AdjustFHEGas,
			tsgx.SgxUint16: 25000 + AdjustFHEGas,
			tsgx.SgxUint32: 25000 + AdjustFHEGas,
			tsgx.SgxUint64: 28000 + AdjustFHEGas,
		},
		SgxEq: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:   41000 + AdjustFHEGas,
			tsgx.SgxUint8:   43000 + AdjustFHEGas,
			tsgx.SgxUint16:  44000 + AdjustFHEGas,
			tsgx.SgxUint32:  72000 + AdjustFHEGas,
			tsgx.SgxUint64:  76000 + AdjustFHEGas,
			tsgx.SgxUint160: 80000 + AdjustFHEGas,
		},
		SgxLe: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  60000 + AdjustFHEGas,
			tsgx.SgxUint8:  72000 + AdjustFHEGas,
			tsgx.SgxUint16: 95000 + AdjustFHEGas,
			tsgx.SgxUint32: 118000 + AdjustFHEGas,
			tsgx.SgxUint64: 146000 + AdjustFHEGas,
		},
		SgxMinMax: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  111000 + AdjustFHEGas,
			tsgx.SgxUint8:  118000 + AdjustFHEGas,
			tsgx.SgxUint16: 143000 + AdjustFHEGas,
			tsgx.SgxUint32: 173000 + AdjustFHEGas,
			tsgx.SgxUint64: 200000 + AdjustFHEGas,
		},
		SgxScalarMinMax: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  111000 + AdjustFHEGas,
			tsgx.SgxUint8:  118000 + AdjustFHEGas,
			tsgx.SgxUint16: 140000 + AdjustFHEGas,
			tsgx.SgxUint32: 154000 + AdjustFHEGas,
			tsgx.SgxUint64: 182000 + AdjustFHEGas,
		},
		SgxNot: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  23000 + AdjustFHEGas,
			tsgx.SgxUint8:  24000 + AdjustFHEGas,
			tsgx.SgxUint16: 25000 + AdjustFHEGas,
			tsgx.SgxUint32: 26000 + AdjustFHEGas,
			tsgx.SgxUint64: 27000 + AdjustFHEGas,
		},
		SgxNeg: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  50000 + AdjustFHEGas,
			tsgx.SgxUint8:  85000 + AdjustFHEGas,
			tsgx.SgxUint16: 121000 + AdjustFHEGas,
			tsgx.SgxUint32: 150000 + AdjustFHEGas,
			tsgx.SgxUint64: 189000 + AdjustFHEGas,
		},
		// TODO: Costs will depend on the complexity of doing reencryption/decryption by the oracle.
		SgxReencrypt: map[tsgx.SgxUintType]uint64{
			tsgx.SgxBool:   1000,
			tsgx.SgxUint4:  1000,
			tsgx.SgxUint8:  1000,
			tsgx.SgxUint16: 1100,
			tsgx.SgxUint32: 1200,
		},
		// As of now, verification costs only cover ciphertext deserialization and assume there is no ZKPoK to verify.
		SgxVerify: map[tsgx.SgxUintType]uint64{
			tsgx.SgxBool:   200,
			tsgx.SgxUint4:  200,
			tsgx.SgxUint8:  200,
			tsgx.SgxUint16: 300,
			tsgx.SgxUint32: 400,
			tsgx.SgxUint64: 800,
		},
		SgxTrivialEncrypt: map[tsgx.SgxUintType]uint64{
			tsgx.SgxBool:   100,
			tsgx.SgxUint4:  100,
			tsgx.SgxUint8:  100,
			tsgx.SgxUint16: 200,
			tsgx.SgxUint32: 300,
			tsgx.SgxUint64: 600,
		},
		// TODO: These will change once we have an FHE-based random generaration.
		SgxRand: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  EvmNetSstoreInitGas + 100000,
			tsgx.SgxUint8:  EvmNetSstoreInitGas + 100000,
			tsgx.SgxUint16: EvmNetSstoreInitGas + 100000,
			tsgx.SgxUint32: EvmNetSstoreInitGas + 100000,
			tsgx.SgxUint64: EvmNetSstoreInitGas + 100000,
		},
		SgxIfThenElse: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint4:  35000 + AdjustFHEGas,
			tsgx.SgxUint8:  37000 + AdjustFHEGas,
			tsgx.SgxUint16: 37000 + AdjustFHEGas,
			tsgx.SgxUint32: 40000 + AdjustFHEGas,
			tsgx.SgxUint64: 43000 + AdjustFHEGas,
		},
		SgxGetCiphertext: map[tsgx.SgxUintType]uint64{
			tsgx.SgxUint8:  12000,
			tsgx.SgxUint16: 14000,
			tsgx.SgxUint32: 18000,
			tsgx.SgxUint64: 28000,
		},
	}
}

var TxDataFractionalGasFactor uint64 = 4

func TxDataFractionalGas(originalGas uint64) (fractionalGas uint64) {
	return originalGas / TxDataFractionalGasFactor
}
