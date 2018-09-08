package psbt

import (
	"github.com/btcsuite/btcd/wire"
	"io"
	"errors"
	"bytes"
	"encoding/binary"
	"github.com/btcsuite/btcd/btcec"
	"fmt"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"encoding/hex"
)

type (

	PSBT struct {
		GlobalUnsignedTx *wire.MsgTx
		Unknown          map[string][]byte
		TxIn             []*PSBTInput
		TxOut            []*PSBTOutput
	}
	PSBTInput struct {
		NonWitnessTx *wire.MsgTx
		WitnessTxOut *wire.TxOut
		PartialSig map[btcutil.AddressPubKey][]byte // or btcec.PublicKey
		SigHashType *uint32
		RedeemScript []byte
		WitnessScript []byte
		FinalScriptSig []byte
		Bip32Derivation map[btcutil.AddressPubKey]*Derivation
		FinalWitness wire.TxWitness
		Unknown map[string][]byte
	}
	PSBTOutput struct {
		RedeemScript []byte
		WitnessScript []byte
		Bip32Derivation map[btcutil.AddressPubKey]*Derivation
		Unknown map[string][]byte
	}
	Derivation struct {
		MasterKeyID uint32
		Path []uint32
	}

	GlobalType uint8
	InputType uint8
	OutputType uint8
)

const (
	GlobalUnsignedTx GlobalType = 0

	InputNonWitnessTx InputType = 0
	InputWitnessTxOut InputType = 1
	InputPartialSig InputType = 2
	InputSigHashType InputType = 3
	InputRedeemScript InputType = 4
	InputWitnessScript InputType = 5
	InputBip32Derivation InputType = 6
	InputFinalScriptSig InputType = 7
	InputFinalWitness InputType = 8

	OutputRedeemScript OutputType = 0
	OutputWitnessScript OutputType = 1
	OutputBip32Derivation OutputType = 2

	MagicStr = "psbt\xff"

	// most long keys are < 40 bytes..z
	maxKeySize = 1000

	// 200kb - twice largest GlobalUnsignedTx size, unless another field is larger?
	maxValueSize = 200000
)

func NewPSBT(tx *wire.MsgTx, unknown map[string][]byte) *PSBT {
	return &PSBT{
		GlobalUnsignedTx: tx,
		Unknown: unknown,
		TxIn: make([]*PSBTInput, len(tx.TxIn)),
		TxOut: make([]*PSBTOutput, len(tx.TxOut)),
	}
}

func ParsePSBT(net *chaincfg.Params, r *bytes.Reader, pver uint32, msgEncoding wire.MessageEncoding) (*PSBT, error) {
	err := readMagic(r, MagicStr)
	if err != nil {
		return nil, err
	}

	fmt.Println("readPsbt")
	psbt, err := psbtFromReader(r, pver, msgEncoding)
	if err != nil {
		return nil, err
	}

	for nIn := 0; nIn < len(psbt.GlobalUnsignedTx.TxIn); nIn++ {
		fmt.Println("readInput")
		psbt.TxIn[nIn], err = psbtInputFromReader(net, r, pver, msgEncoding)
		if err != nil {
			return nil, err
		}
	}

	for nOut := 0; nOut < len(psbt.GlobalUnsignedTx.TxOut); nOut++ {
		fmt.Println("readOutput")
		psbt.TxOut[nOut], err = psbtOutputFromReader(net, r, pver)
		if err != nil {
			return nil, err
		}
	}

	if err = psbt.Validate(); err != nil {
		return nil, err
	}

	return psbt, nil
}

func (p *PSBT) Validate() error {
	if p.GlobalUnsignedTx == nil {
		return errors.New("missing global unsignedTx")
	}
	if len(p.GlobalUnsignedTx.TxIn) != len(p.TxIn) {
		return errors.New("invalid input count")
	}
	if len(p.GlobalUnsignedTx.TxOut) != len(p.TxOut) {
		return errors.New("invalid output count")
	}
	for nIn, pIn := range p.TxIn {
		txIn := p.GlobalUnsignedTx.TxIn[nIn]
		if len(txIn.SignatureScript) > 0 {
			return errors.New("sigScript of unsignedTx should be empty")
		} else if len(txIn.Witness) > 0 {
			return errors.New("witness of unsignedTx should be empty")
		}

		if err := pIn.Validate(); err != nil {
			return err
		}

		if pIn.NonWitnessTx != nil {
			utxoTxId := pIn.NonWitnessTx.TxHash()
			if !utxoTxId.IsEqual(&txIn.PreviousOutPoint.Hash) {
				return errors.New(fmt.Sprintf("non-witnessTx does not belong to txin %d", nIn))
			}
		}
	}

	return nil
}

func (pIn *PSBTInput) Validate() error {
	if pIn.NonWitnessTx != nil && pIn.WitnessTxOut != nil {
		return errors.New("both witness and non-witness utxo data set")
	}
	return nil
}

func (d *Derivation) SerializeSize() int {
	return len(d.Path)*4+4
}

func (d *Derivation) Serialize(w io.Writer) (int, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], d.MasterKeyID)
	n, err := w.Write(buf[:])
	if err != nil {
		return n, err
	}
	for i := 0; i < len(d.Path); i++ {
		binary.BigEndian.PutUint32(buf[:], d.Path[i])
		nn, err := w.Write(buf[:])
		if err != nil {
			return n, err
		}
		n += nn
	}
	return n, nil
}

// readMagic reads len(magic) bytes from the reader, and checks
// them against `magic`. if no error ir returned, the bytes matched
func readMagic(r io.Reader, magic string) (error) {
	readMagic := make([]byte, len(magic))
	_, err := io.ReadFull(r, readMagic)
	if err != nil {
		return err
	}
	if string(readMagic) != MagicStr {
		return errors.New(`invalid magic prefix`)
	}
	return nil
}

func readKeyValue(r io.Reader, pver uint32) ([]byte, []byte, error) {
	key, err := wire.ReadVarBytes(r, pver, maxKeySize, "map key")
	if err != nil {
		return nil, nil, err
	}
	if len(key) == 0 {
		return nil, nil, nil
	}
	value, err := wire.ReadVarBytes(r, pver, maxValueSize, "map value")
	if err != nil {
		return nil, nil, err
	}

	return key, value, nil
}
// parseMap parses the next map to be read. This function
// ensures that no duplicates exist, and key lengths are >0

func writeMap(w io.Writer, pver uint32, key string, value []byte) error {
	err := wire.WriteVarBytes(w, pver, []byte(key))
	if err != nil {
		return err
	}
	return wire.WriteVarBytes(w, pver, value)
}

// psbtFromMap takes a map of key/values, and returns a PSBT
// initialized with its global section, or an error if unsuccessful
// assumes no duplicate keys and key lengths > 0
func psbtFromReader(r io.Reader, pver uint32, msgFormat wire.MessageEncoding) (*PSBT, error) {
	var globalTx *wire.MsgTx
	var unknown map[string][]byte
	for {
		keyBytes, value, err := readKeyValue(r, pver)
		if err != nil {
			return nil, err
		}
		if len(keyBytes) == 0 {
			break
		}
		key := GlobalType(keyBytes[0])
		switch key {
		case GlobalUnsignedTx:
			if len(keyBytes) != 1 {
				return nil, errors.New("invalid global tx key length")
			}
			tx := &wire.MsgTx{}
			err := tx.BtcDecode(bytes.NewReader(value), pver, msgFormat)
			if err != nil {
				return nil, err
			}
			globalTx = tx
		default:
			if unknown == nil {
				unknown = make(map[string][]byte, 1)
			}
			unknown[string(keyBytes)] = value
		}
	}
	if globalTx == nil {
		return nil, errors.New("missing global unsigned tx for psbt")
	}
	psbt := NewPSBT(globalTx, unknown)
	return psbt, nil
}

// readDerivation deserializes a bip32 derivation value, or returns
// an error if unsuccessful
func readDerivation(deriv []byte) (*Derivation, error) {
	if len(deriv) == 0 || len(deriv) % 4 != 0 {
		return nil, errors.New("invalid bip32 derivation length")
	}
	pathLen := (len(deriv) / 4) - 1
	d := &Derivation{
		MasterKeyID: binary.BigEndian.Uint32(deriv[0:4]),
		Path: make([]uint32, pathLen),
	}
	for i := 0; i < pathLen; i++ {
		d.Path[i] = binary.BigEndian.Uint32(deriv[4+i*4:8+i*4])
	}
	return d, nil
}

func psbtInputToMap(input *PSBTInput, pver uint32) ([]byte, error) {
	kvWriter := bytes.NewBuffer(nil)
	if input.NonWitnessTx != nil {
		txBuf := bytes.NewBuffer(make([]byte, 0, input.NonWitnessTx.SerializeSize()))
		err := input.NonWitnessTx.Serialize(txBuf)
		if err != nil {
			return nil, err
		}
		err = writeMap(kvWriter, pver, string(InputNonWitnessTx), txBuf.Bytes())
		if err != nil {
			return nil, err
		}
	} else if input.WitnessTxOut != nil {
		txOutWriter := bytes.NewBuffer(make([]byte, 0, input.WitnessTxOut.SerializeSize()))
		err := wire.WriteTxOut(txOutWriter, pver, 0, input.WitnessTxOut)
		if err != nil {
			return nil, err
		}
		err = writeMap(kvWriter, pver, string(InputWitnessTxOut), txOutWriter.Bytes())
		if err != nil {
			return nil, err
		}
	}

	if len(input.PartialSig) > 0 {
		for key, sig := range input.PartialSig {
			err := writeMap(kvWriter, pver, string(InputPartialSig) + string(key.ScriptAddress()), sig)
			if err != nil {
				return nil, err
			}
		}
	}

	if input.SigHashType != nil {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], *input.SigHashType)

		err := writeMap(kvWriter, pver, string(InputSigHashType), buf[:])
		if err != nil {
			return nil, err
		}
	}

	if len(input.RedeemScript) > 0 {
		err := writeMap(kvWriter, pver, string(InputRedeemScript), input.RedeemScript)
		if err != nil {
			return nil, err
		}
	}

	if len(input.WitnessScript) > 0 {
		err := writeMap(kvWriter, pver, string(InputWitnessScript), input.WitnessScript)
		if err != nil {
			return nil, err
		}
	}

	if len(input.Bip32Derivation) > 0 {
		for key, keyInfo := range input.Bip32Derivation {
			w := bytes.NewBuffer(make([]byte, keyInfo.SerializeSize()))
			_, err := keyInfo.Serialize(w)
			if err != nil {
				return nil, err
			}
			err = writeMap(kvWriter, pver, string(InputBip32Derivation) + string(key.ScriptAddress()), w.Bytes())
			if err != nil {
				return nil, err
			}
		}
	}

	if len(input.FinalScriptSig) > 0 {
		err := writeMap(kvWriter, pver, string(InputFinalScriptSig), input.FinalScriptSig)
		if err != nil {
			return nil, err
		}
	}

	if len(input.FinalWitness) > 0 {
		w := bytes.NewBuffer(make([]byte, input.FinalWitness.SerializeSize()))
		err := wire.WriteVarInt(w, pver, uint64(len(input.FinalWitness)))
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(input.FinalWitness); i++ {
			err = wire.WriteVarBytes(w, pver, input.FinalWitness[i])
			if err != nil {
				return nil, err
			}
		}
		err = writeMap(kvWriter, pver, string(InputFinalWitness), w.Bytes())
		if err != nil {
			return nil, err
		}
	}

	for key, value := range input.Unknown {
		err := writeMap(kvWriter, pver, key, value)
		if err != nil {
			return nil, err
		}
	}

	return kvWriter.Bytes(), nil
}


// psbtInputFromReader takes an input map section and produces a PSBTInput,
// or an error if unsuccessful. assumes no duplicate keys and key lengths > 0
func psbtInputFromReader(net *chaincfg.Params, r io.Reader, pver uint32, msgEncoding wire.MessageEncoding) (*PSBTInput, error) {
	input := &PSBTInput{}
	for {
		keyBytes, value, err := readKeyValue(r, pver)
		if err != nil {
			return nil, err
		}
		if len(keyBytes) == 0 {
			break
		}
		key := InputType(keyBytes[0])
		fmt.Printf("input %s keybytes\n", hex.EncodeToString(keyBytes))
		fmt.Printf("input key %d\n", key)
		fmt.Printf("input %s valbytes\n", hex.EncodeToString(value))
		switch key {
		case InputNonWitnessTx:
			if input.NonWitnessTx != nil {
				return nil, errors.New("duplicate non-witness tx")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid non-witness tx key length")
			}
			tx := &wire.MsgTx{}
			err := tx.BtcDecode(bytes.NewReader(value), pver, msgEncoding)
			if err != nil {
				return nil, err
			}
			input.NonWitnessTx = tx
		case InputWitnessTxOut:
			if input.WitnessTxOut != nil {
				return nil, errors.New("duplicate witness txout")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid witness txout key length")
			}
			amtBytes := make([]byte, 8)
			txOutReader := bytes.NewReader(value)
			_, err := io.ReadFull(txOutReader, amtBytes)
			if err != nil {
				fmt.Println("read value")
				return nil, err
			}

			script, err := wire.ReadVarBytes(txOutReader, pver, maxKeySize, "txOut script")
			if err != nil {
				fmt.Println("read script")
				return nil, err
			}

			input.WitnessTxOut = wire.NewTxOut(int64(binary.LittleEndian.Uint64(amtBytes)), script)
		case InputPartialSig:
			if len(keyBytes) != 1 + btcec.PubKeyBytesLenCompressed && len(keyBytes) != 1 + btcec.PubKeyBytesLenUncompressed {
				return nil, errors.New("invalid public key length1")
			}
			pubKeyAddr, err := btcutil.NewAddressPubKey(keyBytes[1:], net)
			if err != nil {
				return nil, err
			}
			if input.PartialSig == nil {
				input.PartialSig = make(map[btcutil.AddressPubKey][]byte, 1)
			}
			if _, exists := input.PartialSig[*pubKeyAddr]; exists {
				return nil, errors.New("duplicate partial sig")
			}
			input.PartialSig[*pubKeyAddr] = value
		case InputSigHashType:
			if input.SigHashType != nil {
				return nil, errors.New("duplicate sighash type")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid sighash key length")
			} else if len(value) != 4 {
				return nil, errors.New("invalid sighash value length")
			}
			sigHashType := binary.BigEndian.Uint32(value)
			input.SigHashType = &sigHashType
		case InputRedeemScript:
			if input.RedeemScript != nil {
				return nil, errors.New("duplicate redeemscript")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid redeemscript key length")
			}
			input.RedeemScript = value
		case InputWitnessScript:
			if input.WitnessScript != nil {
				return nil, errors.New("duplicate witnessscript")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid witnessscript key length")
			}
			input.WitnessScript = value
		case InputBip32Derivation:
			if len(keyBytes) != 1 + btcec.PubKeyBytesLenCompressed && len(keyBytes) != 1 + btcec.PubKeyBytesLenUncompressed {
				return nil, errors.New(fmt.Sprintf("invalid public key length2, %d %s", len(keyBytes), hex.EncodeToString(keyBytes)))
			}
			publicKey, err := btcutil.NewAddressPubKey(keyBytes[1:], net)
			if err != nil {
				return nil, err
			}
			if nil == input.Bip32Derivation {
				input.Bip32Derivation = make(map[btcutil.AddressPubKey]*Derivation)
			}
			if _, exists := input.Bip32Derivation[*publicKey]; exists {
				return nil, errors.New("duplicate bip32 derivation")
			}
			input.Bip32Derivation[*publicKey], err = readDerivation(value)
			if err != nil {
				return nil, err
			}
		case InputFinalScriptSig:
			if len(input.FinalScriptSig) > 0 {
				return nil, errors.New("duplicate final scriptSig")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid final scriptsig key length")
			}
			input.FinalScriptSig = value
		case InputFinalWitness:
			if len(input.FinalWitness) > 0 {
				return nil, errors.New("duplicate final witness")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid final witness key length")
			}
			witnessReader := bytes.NewReader(value)
			witnessSize, err := wire.ReadVarInt(witnessReader, pver)
			if err != nil {
				return nil, err
			}
			input.FinalWitness = make([][]byte, witnessSize)
			for i := uint64(0); i < witnessSize; i++ {
				input.FinalWitness[i], err = wire.ReadVarBytes(witnessReader, pver, 10000, "final witness element")
			}
		default:
			if input.Unknown == nil {
				input.Unknown = make(map[string][]byte)
			}
			if _, exists := input.Unknown[string(keyBytes)]; exists {
				return nil, errors.New("duplicate unknown key")
			}
			input.Unknown[string(keyBytes)] = value
		}
	}

	return input, nil
}

// psbtOutputFromMap takes an output map section and produces a PSBTOutput,
// or an error if unsuccessful. assumes no duplicate keys and key lengths > 0
func psbtOutputFromReader(net *chaincfg.Params, r io.Reader, pver uint32) (*PSBTOutput, error) {
	output := &PSBTOutput{}
	for {
		keyBytes, err := wire.ReadVarBytes(r, pver, maxKeySize, "map key")
		if err != nil {
			return nil, err
		}
		if len(keyBytes) == 0 {
			break
		}
		keyStr := string(keyBytes)
		value, err := wire.ReadVarBytes(r, pver, maxValueSize, "map value")
		if err != nil {
			return nil, err
		}
		// requires >0 keyStr len
		// assumes no duplicate keys
		key := OutputType(keyBytes[0])
		switch key {
		case OutputRedeemScript:
			if len(keyStr) != 1 {
				return nil, errors.New("invalid redeemscript key length")
			}
			output.RedeemScript = value
		case OutputWitnessScript:
			if len(keyStr) != 1 {
				return nil, errors.New("invalid witnessscript key length")
			}
			output.WitnessScript = value
		case OutputBip32Derivation:
			if len(keyBytes) != 1 + btcec.PubKeyBytesLenCompressed && len(keyBytes) != 1 + btcec.PubKeyBytesLenUncompressed {
				return nil, errors.New("invalid public key length3")
			}
			fmt.Printf("pubkey: %s\n", keyBytes[1:])
			publicKey, err := btcutil.NewAddressPubKey(keyBytes[1:], net)
			if err != nil {
				return nil, err
			}
			if nil == output.Bip32Derivation {
				output.Bip32Derivation = make(map[btcutil.AddressPubKey]*Derivation)
			}
			if _, exists := output.Bip32Derivation[*publicKey]; exists {
				return nil, errors.New("duplicate partial sig")
			}
			output.Bip32Derivation[*publicKey], err = readDerivation(value)
			if err != nil {
				return nil, err
			}
		default:
			if output.Unknown == nil {
				output.Unknown = make(map[string][]byte)
			}
			output.Unknown[keyStr] = value
		}
	}

	return output, nil
}

func psbtOutputToMap(output *PSBTOutput, pver uint32) (map[string][]byte, error) {
	outputMap := make(map[string][]byte)
	if len(output.RedeemScript) > 0 {
		outputMap[string(InputRedeemScript)] = output.RedeemScript
	}

	if len(output.WitnessScript) > 0 {
		outputMap[string(InputWitnessScript)] = output.WitnessScript
	}

	if len(output.Bip32Derivation) > 0 {
		for key, keyInfo := range output.Bip32Derivation {
			w := bytes.NewBuffer(make([]byte, keyInfo.SerializeSize()))
			_, err := keyInfo.Serialize(w)
			if err != nil {
				return nil, err
			}
			outputMap[string(InputBip32Derivation) + string(key.ScriptAddress())] = w.Bytes()
		}
	}

	return outputMap, nil
}