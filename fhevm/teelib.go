package fhevm

// Mapping between function signatures and the functions to call
var signatureToTeeLibMethod = map[uint32]*FheLibMethod{}

func GetTeeLibMethod(signature uint32) (teeLibMethod *FheLibMethod, found bool) {
	teeLibMethod, found = signatureToTeeLibMethod[signature]
	return
}

// All methods available in the teelib precompile
var teelibMethods = []*FheLibMethod{
	// TEE operations
	{
		name:                "teeEncrypt",
		argTypes:            "(uint256,bytes1)",
		requiredGasFunction: teeEncryptRequiredGas,
		runFunction:         teeEncryptRun,
	},
	{
		name:                "teeDecrypt",
		argTypes:            "(uint256)",
		requiredGasFunction: teeDecryptRequiredGas,
		runFunction:         teeDecryptRun,
	},
	{
		name:                "teeAdd",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeAddSubRequiredGas,
		runFunction:         teeAddRun,
	},
	{
		name:                "teeSub",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeAddSubRequiredGas,
		runFunction:         teeSubRun,
	},
	{
		name:                "teeMul",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeMulRequiredGas,
		runFunction:         teeMulRun,
	},
	{
		name:                "teeDiv",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeDivRequiredGas,
		runFunction:         teeDivRun,
	},
	{
		name:                "teeRem",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeRemRequiredGas,
		runFunction:         teeRemRun,
	},
	{
		name:                "teeLe",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeLeRun,
	},
	{
		name:                "teeLt",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeLtRun,
	},
	{
		name:                "teeEq",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeEqRun,
	},
	{
		name:                "teeGe",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeGeRun,
	},
	{
		name:                "teeGt",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeGtRun,
	},
	{
		name:                "teeNe",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeNeRun,
	},
	{
		name:                "teeMin",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeMinRun,
	},
	{
		name:                "teeMax",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeMaxRun,
	},
	{
		name:                "teeSelect",
		argTypes:            "(uint256,uint256,uint256)",
		requiredGasFunction: teeComparisonRequiredGas,
		runFunction:         teeSelectRun,
	},
	{
		name:                "teeShl",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeShiftRequiredGas,
		runFunction:         teeShlRun,
	},
	{
		name:                "teeShr",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeShiftRequiredGas,
		runFunction:         teeShrRun,
	},
	{
		name:                "teeRotl",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeShiftRequiredGas,
		runFunction:         teeRotlRun,
	},
	{
		name:                "teeRotr",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeShiftRequiredGas,
		runFunction:         teeRotrRun,
	},
	{
		name:                "teeBitAnd",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeBitwiseOpRequiredGas,
		runFunction:         teeBitAndRun,
	},
	{
		name:                "teeBitOr",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeBitwiseOpRequiredGas,
		runFunction:         teeBitOrRun,
	},
	{
		name:                "teeBitXor",
		argTypes:            "(uint256,uint256,bytes1)",
		requiredGasFunction: teeBitwiseOpRequiredGas,
		runFunction:         teeBitXorRun,
	},
	{
		name:                "teeNeg",
		argTypes:            "(uint256)",
		requiredGasFunction: teeNegRequiredGas,
		runFunction:         teeNegRun,
	},
	{
		name:                "teeNot",
		argTypes:            "(uint256)",
		requiredGasFunction: teeNotRequiredGas,
		runFunction:         teeNotRun,
	},
	{
		name:                "teeCast",
		argTypes:            "(uint256,bytes1)",
		requiredGasFunction: teeCastRequiredGas,
		runFunction:         teeCastRun,
	},
}

func init() {
	// create the mapping for every available fhelib method
	for _, method := range teelibMethods {
		signatureToTeeLibMethod[method.Signature()] = method
	}

}
