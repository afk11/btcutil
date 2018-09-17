package psbt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

type (
	// Tx is the main structure of a partially signed transaction
	Tx struct {
		GlobalUnsignedTx *wire.MsgTx
		Unknown          *UnknownKVList
		TxIn             []*TxIn
		TxOut            []*TxOut
	}

	// TxIn contains information about a wire.TxIn
	TxIn struct {
		NonWitnessTx    *wire.MsgTx
		WitnessTxOut    *wire.TxOut
		PartialSig      *PartialSigList // or btcec.PublicKey
		SigHashType     *uint32
		RedeemScript    []byte
		WitnessScript   []byte
		FinalScriptSig  []byte
		Bip32Derivation *DerivationList
		FinalWitness    wire.TxWitness
		Unknown         *UnknownKVList
	}

	// TxOut contains information about a wire.TxOut
	TxOut struct {
		RedeemScript    []byte
		WitnessScript   []byte
		Bip32Derivation *DerivationList
		Unknown         *UnknownKVList
	}

	// Derivation contains information about a bip32 derivation
	Derivation struct {
		MasterKeyID uint32
		Path        []uint32
	}

	// DerivationList implements a unique map of public keys, associated
	// with their derivations
	DerivationList struct {
		list []*Derivation
		dmap map[btcutil.AddressPubKey]int
	}

	// PartialSigList implements a unique map of public keys, associated
	// with their signature
	PartialSigList struct {
		list [][]byte
		dmap map[btcutil.AddressPubKey]int
	}

	// UnknownKVList implements a unique map of unknown keys, associated
	// with their values
	UnknownKVList struct {
		list [][]byte
		dmap map[string]int
	}

	// GlobalType is a category of keys belonging to a psbt.Tx global section
	GlobalType uint8

	// InputType is a category of keys belonging to a psbt.TxIn
	InputType uint8

	// OutputType is a category of keys belonging to a psbt.TxOut
	OutputType uint8
)

const (
	// GlobalUnsignedTx is the GlobalType for the Tx unsigned transaction
	GlobalUnsignedTx GlobalType = 0

	// InputNonWitnessTx is the InputType for the PSBTInputs non-witness wire.TX
	InputNonWitnessTx InputType = 0

	// InputWitnessTxOut is the InputType for the PSBTInputs witness wire.TxOut
	InputWitnessTxOut InputType = 1

	// InputPartialSig is the InputType for the PSBTInputs partial signatures
	InputPartialSig InputType = 2

	// InputSigHashType is the InputType for the PSBTInputs sighash type
	InputSigHashType InputType = 3

	// InputRedeemScript is the InputType for the PSBTInputs redeemscript
	InputRedeemScript InputType = 4

	// InputWitnessScript is the InputType for the PSBTInputs witnessscript
	InputWitnessScript InputType = 5

	// InputBip32Derivation is the InputType for the PSBTInputs bip32 derivations
	InputBip32Derivation InputType = 6

	// InputFinalScriptSig is the InputType for the PSBTInputs final scriptSig
	InputFinalScriptSig InputType = 7

	// InputFinalWitness is the InputType for the PSBTInputs final scriptWitness
	InputFinalWitness InputType = 8

	// OutputRedeemScript is the OutputType for the PSBTOutputs redeemscript
	OutputRedeemScript OutputType = 0

	// OutputWitnessScript is the OutputType for the PSBTOutputs witnessscript
	OutputWitnessScript OutputType = 1

	// OutputBip32Derivation is the OutputType for the PSBTOutputs bip32 derivations
	OutputBip32Derivation OutputType = 2

	// MagicStr is the magic bytes prefixing a correctly encoded Tx
	MagicStr = "psbt\xff"

	// most long keys are < 40 bytes..z
	maxKeySize = 1000

	// 200kb - twice largest GlobalUnsignedTx size, unless another field is larger?
	maxValueSize = 200000
)

// SerializeSize returns the size required to encode the Derivation
func (d *Derivation) SerializeSize() int {
	return len(d.Path)*4 + 4
}

// Serialize serializes the Derivation into the provided io.Writer
func (d *Derivation) Serialize(w io.Writer) (int, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], d.MasterKeyID)
	n, err := w.Write(buf[:])
	if err != nil {
		return n, err
	}
	for i := 0; i < len(d.Path); i++ {
		binary.LittleEndian.PutUint32(buf[:], d.Path[i])
		nn, err := w.Write(buf[:])
		if err != nil {
			return n, err
		}
		n += nn
	}
	return n, nil
}

// NewUnknownList returns a fully initialized *UnknownKVList
func NewUnknownList() *UnknownKVList {
	return &UnknownKVList{
		dmap: make(map[string]int),
		list: make([][]byte, 0),
	}
}

// Append adds the k/v pair to the map, returning nil,
// or an error upon a duplicate
func (l *UnknownKVList) Append(k string, v []byte) error {
	if len(k) == 0 {
		return errors.New("key cannot be empty")
	}
	if _, exists := l.dmap[k]; exists {
		return errors.New("duplicate unknown key")
	}
	l.dmap[k] = len(l.list)
	l.list = append(l.list, v)
	return nil
}

// UnknownKVs returns an ordered slice containing keys, plus a slice
// containing values. They are ordered in the same as they were Appended
func (l *UnknownKVList) UnknownKVs() (keys []string, values [][]byte) {
	if len(l.list) > 0 {
		keys = make([]string, len(l.list))
		values = make([][]byte, len(l.list))
		for key, idx := range l.dmap {
			keys[idx] = key
			values[idx] = l.list[idx]
		}
	}
	return keys, values
}

// NewDerivationList returns a fully initialized *DerivationList
func NewDerivationList() *DerivationList {
	return &DerivationList{
		dmap: make(map[btcutil.AddressPubKey]int),
		list: make([]*Derivation, 0),
	}
}

// Append adds the k/v pair to the map, returning nil,
// or an error upon a duplicate
func (l *DerivationList) Append(k btcutil.AddressPubKey, d *Derivation) error {
	if _, exists := l.dmap[k]; exists {
		return errors.New("derivation already exists")
	}
	l.dmap[k] = len(l.list)
	l.list = append(l.list, d)
	return nil
}

// Derivations returns an ordered slice containing keys, plus a slice
// containing Derivations. They are ordered in the same as they were Appended
func (l *DerivationList) Derivations() (keys []*btcutil.AddressPubKey, derivs []*Derivation) {
	if len(l.list) > 0 {
		keys = make([]*btcutil.AddressPubKey, len(l.list))
		derivs = make([]*Derivation, len(l.list))
		for key, idx := range l.dmap {
			k := key
			keys[idx] = &k
			derivs[idx] = l.list[idx]
		}
	}

	return keys, derivs
}

// NewPartialSigList returns a fully initialized *PartialSigList
func NewPartialSigList() *PartialSigList {
	return &PartialSigList{
		dmap: make(map[btcutil.AddressPubKey]int),
		list: make([][]byte, 0),
	}
}

// Append adds the k/v pair to the map, returning nil,
// or an error upon a duplicate
func (l *PartialSigList) Append(k btcutil.AddressPubKey, sig []byte) error {
	if _, exists := l.dmap[k]; exists {
		return errors.New("derivation already exists")
	}
	l.dmap[k] = len(l.list)
	l.list = append(l.list, sig)
	return nil
}

// Signatures returns an ordered slice containing keys, plus a slice
// containing signatures. They are ordered in the same as they were Appended
func (l *PartialSigList) Signatures() (keys []*btcutil.AddressPubKey, sigs [][]byte) {
	n := len(l.list)
	if n > 0 {
		keys = make([]*btcutil.AddressPubKey, len(l.list))
		sigs = make([][]byte, len(l.list))
		for key, idx := range l.dmap {
			k := key
			keys[idx] = &k
			sigs[idx] = l.list[idx]
		}
	}

	return keys, sigs
}

// ParsePSBT takes a reader and attempts to parse the psbt.Tx.
// msgEnc may be passed to indicate the callers preference for
// the TxIn NonWitnessTx,
func ParsePSBT(net *chaincfg.Params, r io.Reader, pver uint32, msgEncoding wire.MessageEncoding) (*Tx, error) {
	readMagic := make([]byte, len(MagicStr))
	_, err := io.ReadFull(r, readMagic)
	if err != nil {
		return nil, err
	}
	if string(readMagic) != MagicStr {
		return nil, errors.New(`invalid magic prefix`)
	}

	psbt, err := readGlobals(r, pver)
	if err != nil {
		return nil, err
	}

	for nIn := 0; nIn < len(psbt.GlobalUnsignedTx.TxIn); nIn++ {
		psbt.TxIn[nIn], err = readInput(net, r, pver, msgEncoding)
		if err != nil {
			return nil, err
		}
	}

	for nOut := 0; nOut < len(psbt.GlobalUnsignedTx.TxOut); nOut++ {
		psbt.TxOut[nOut], err = readOutput(net, r, pver)
		if err != nil {
			return nil, err
		}
	}

	if err = psbt.Validate(); err != nil {
		return nil, err
	}

	return psbt, nil
}

// Encode returns a slice containing the encoded PSBT, or an error upon failure
func (p *Tx) Encode(pver uint32, msgEncoding wire.MessageEncoding) ([]byte, error) {
	b := bytes.NewBuffer(nil)
	_, err := b.Write([]byte(MagicStr))
	if err != nil {
		return nil, err
	}

	err = writeGlobals(b, p, pver)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(p.GlobalUnsignedTx.TxIn); i++ {
		err = writeInput(b, p.TxIn[i], pver, msgEncoding)
		if err != nil {
			return nil, err
		}
	}

	for i := 0; i < len(p.GlobalUnsignedTx.TxOut); i++ {
		err = writeOutput(b, p.TxOut[i], pver)
		if err != nil {
			return nil, err
		}
	}

	return b.Bytes(), nil
}

// Validate performs sanity checks on a fully constructed PSBT
func (p *Tx) Validate() error {
	if p.GlobalUnsignedTx == nil {
		return errors.New("missing global unsigned tx")
	}
	if len(p.GlobalUnsignedTx.TxIn) != len(p.TxIn) {
		return errors.New("invalid input count")
	}
	if len(p.GlobalUnsignedTx.TxOut) != len(p.TxOut) {
		return errors.New("invalid output count")
	}
	for nIn, input := range p.TxIn {
		txIn := p.GlobalUnsignedTx.TxIn[nIn]
		if len(txIn.SignatureScript) > 0 {
			return errors.New("scriptSig of global unsigned tx should be empty")
		} else if len(txIn.Witness) > 0 {
			return errors.New("witness of global unsigned tx should be empty")
		}

		if err := input.Validate(); err != nil {
			return err
		}

		if input.NonWitnessTx != nil {
			txID := input.NonWitnessTx.TxHash()
			utxo := txIn.PreviousOutPoint
			if !txID.IsEqual(&utxo.Hash) {
				return fmt.Errorf("non-witnessTx %s does not belong to txin %d (%s,%d)",
					txID.String(), nIn, utxo.Hash.String(), utxo.Index)
			}
		}
	}

	return nil
}

// Validate performs sanity checks on the TxIn
func (i *TxIn) Validate() error {
	if i.NonWitnessTx != nil && i.WitnessTxOut != nil {
		return errors.New("both witness and non-witness utxo data set")
	}
	return nil
}

// readKeyValue takes an io.Reader and returns the next key / value tuple
// from a psbt map. It returns an error if a parsing error occurred, and
// len(key) may equal zero if reading the map termination byte
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

// readDerivation deserializes a bip32 derivation value, or returns
// an error if unsuccessful
func readDerivation(deriv []byte) (*Derivation, error) {
	if len(deriv) == 0 || len(deriv)%4 != 0 {
		return nil, errors.New("invalid bip32 derivation length")
	}
	pathLen := (len(deriv) / 4) - 1
	d := &Derivation{
		MasterKeyID: binary.BigEndian.Uint32(deriv[0:4]),
		Path:        make([]uint32, pathLen),
	}
	for i := 0; i < pathLen; i++ {
		d.Path[i] = binary.LittleEndian.Uint32(deriv[4+i*4 : 8+i*4])
	}
	return d, nil
}

// readTxOut decodes a wire.TxOut from an io.Reader
func readTxOut(r io.Reader, pver uint32) (*wire.TxOut, error) {
	amtBytes := make([]byte, 8)
	_, err := io.ReadFull(r, amtBytes)
	if err != nil {
		return nil, err
	}

	script, err := wire.ReadVarBytes(r, pver, maxKeySize, "txOut script")
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(int64(binary.LittleEndian.Uint64(amtBytes)), script), nil
}

// psbtFromMap takes a map of key/values, and returns a Tx
// initialized with its global section, or an error if unsuccessful
func readGlobals(r io.Reader, pver uint32) (*Tx, error) {
	psbt := &Tx{}
	for {
		keyBytes, value, err := readKeyValue(r, pver)
		if err != nil {
			return nil, err
		}
		if len(keyBytes) == 0 {
			break
		}
		switch GlobalType(keyBytes[0]) {
		case GlobalUnsignedTx:
			if psbt.GlobalUnsignedTx != nil {
				return nil, errors.New("duplicate global tx")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid global tx key length")
			}
			tx := &wire.MsgTx{}
			err := tx.BtcDecode(bytes.NewReader(value), pver, wire.BaseEncoding)
			if err != nil {
				return nil, err
			}
			psbt.GlobalUnsignedTx = tx
		default:
			if psbt.Unknown == nil {
				psbt.Unknown = NewUnknownList()
			}
			err = psbt.Unknown.Append(string(keyBytes), value)
			if err != nil {
				return nil, err
			}
		}
	}
	if psbt.GlobalUnsignedTx == nil {
		return nil, errors.New("missing global unsigned tx for psbt")
	}
	psbt.TxIn = make([]*TxIn, len(psbt.GlobalUnsignedTx.TxIn))
	psbt.TxOut = make([]*TxOut, len(psbt.GlobalUnsignedTx.TxOut))
	return psbt, nil
}

// readInput takes an input map section and produces a psbt.TxIn,
// or an error if unsuccessful.
func readInput(net *chaincfg.Params, r io.Reader, pver uint32, msgEncoding wire.MessageEncoding) (*TxIn, error) {
	input := &TxIn{}
	for {
		keyBytes, value, err := readKeyValue(r, pver)
		if err != nil {
			return nil, err
		}
		if len(keyBytes) == 0 {
			break
		}
		switch InputType(keyBytes[0]) {
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

			input.WitnessTxOut, err = readTxOut(bytes.NewReader(value), pver)
			if err != nil {
				return nil, err
			}
		case InputPartialSig:
			if len(keyBytes) != 1+btcec.PubKeyBytesLenCompressed && len(keyBytes) != 1+btcec.PubKeyBytesLenUncompressed {
				return nil, errors.New("invalid public key length")
			}
			pubKeyAddr, err := btcutil.NewAddressPubKey(keyBytes[1:], net)
			if err != nil {
				return nil, err
			}
			if input.PartialSig == nil {
				input.PartialSig = NewPartialSigList()
			}
			err = input.PartialSig.Append(*pubKeyAddr, value)
			if err != nil {
				return nil, err
			}
		case InputSigHashType:
			if input.SigHashType != nil {
				return nil, errors.New("duplicate sighash type")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid sighash key length")
			} else if len(value) != 4 {
				return nil, errors.New("invalid sighash value length")
			}
			sigHashType := binary.LittleEndian.Uint32(value)
			input.SigHashType = &sigHashType
		case InputRedeemScript:
			if len(input.RedeemScript) > 0 {
				return nil, errors.New("duplicate redeemscript")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid redeemscript key length")
			}
			input.RedeemScript = value
		case InputWitnessScript:
			if len(input.WitnessScript) > 0 {
				return nil, errors.New("duplicate witnessscript")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid witnessscript key length")
			}
			input.WitnessScript = value
		case InputBip32Derivation:
			if len(keyBytes) != 1+btcec.PubKeyBytesLenCompressed && len(keyBytes) != 1+btcec.PubKeyBytesLenUncompressed {
				return nil, errors.New("invalid public key length")
			}
			publicKey, err := btcutil.NewAddressPubKey(keyBytes[1:], net)
			if err != nil {
				return nil, err
			}
			derivation, err := readDerivation(value)
			if err != nil {
				return nil, err
			}
			if nil == input.Bip32Derivation {
				input.Bip32Derivation = NewDerivationList()
			}
			err = input.Bip32Derivation.Append(*publicKey, derivation)
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
				input.Unknown = NewUnknownList()
			}
			err = input.Unknown.Append(string(keyBytes), value)
			if err != nil {
				return nil, err
			}
		}
	}

	return input, nil
}

// readOutput takes an output map section and produces a psbt.TxOut,
// or an error if unsuccessful. assumes no duplicate keys and key lengths > 0
func readOutput(net *chaincfg.Params, r io.Reader, pver uint32) (*TxOut, error) {
	output := &TxOut{}
	for {
		keyBytes, value, err := readKeyValue(r, pver)
		if err != nil {
			return nil, err
		}
		if len(keyBytes) == 0 {
			break
		}
		switch OutputType(keyBytes[0]) {
		case OutputRedeemScript:
			if len(output.RedeemScript) > 0 {
				return nil, errors.New("duplicate redeemscript")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid redeemscript key length")
			}
			output.RedeemScript = value
		case OutputWitnessScript:
			if len(output.WitnessScript) > 0 {
				return nil, errors.New("duplicate witnessscript")
			} else if len(keyBytes) != 1 {
				return nil, errors.New("invalid witnessscript key length")
			}
			output.WitnessScript = value
		case OutputBip32Derivation:
			if len(keyBytes) != 1+btcec.PubKeyBytesLenCompressed && len(keyBytes) != 1+btcec.PubKeyBytesLenUncompressed {
				return nil, errors.New("invalid public key length")
			}
			publicKey, err := btcutil.NewAddressPubKey(keyBytes[1:], net)
			if err != nil {
				return nil, err
			}
			if nil == output.Bip32Derivation {
				output.Bip32Derivation = NewDerivationList()
			}
			derivation, err := readDerivation(value)
			err = output.Bip32Derivation.Append(*publicKey, derivation)
			if err != nil {
				return nil, err
			}
			if err != nil {
				return nil, err
			}
		default:
			if output.Unknown == nil {
				output.Unknown = NewUnknownList()
			}
			err = output.Unknown.Append(string(keyBytes), value)
			if err != nil {
				return nil, err
			}
		}
	}

	return output, nil
}

func writeKeyValue(w io.Writer, pver uint32, key string, value []byte) error {
	err := wire.WriteVarBytes(w, pver, []byte(key))
	if err != nil {
		return err
	}
	return wire.WriteVarBytes(w, pver, value)
}

func writeWitness(w io.Writer, pver uint32, wit wire.TxWitness) error {
	err := wire.WriteVarInt(w, pver, uint64(len(wit)))
	if err != nil {
		return err
	}
	for i := 0; i < len(wit); i++ {
		err = wire.WriteVarBytes(w, pver, wit[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func writeGlobals(w io.Writer, psbt *Tx, pver uint32) error {
	if psbt.GlobalUnsignedTx != nil {
		txBuf := bytes.NewBuffer(make([]byte, 0, psbt.GlobalUnsignedTx.SerializeSize()))
		err := psbt.GlobalUnsignedTx.BtcEncode(txBuf, 0, wire.BaseEncoding)
		if err != nil {
			return err
		}
		err = writeKeyValue(w, pver, string(GlobalUnsignedTx), txBuf.Bytes())
		if err != nil {
			return err
		}
	}

	if psbt.Unknown != nil {
		keys, values := psbt.Unknown.UnknownKVs()
		for i := 0; i < len(keys); i++ {
			err := writeKeyValue(w, pver, keys[i], values[i])
			if err != nil {
				return err
			}
		}
	}

	err := wire.WriteVarBytes(w, pver, nil)
	if err != nil {
		return err
	}

	return nil
}

func writeInput(w io.Writer, input *TxIn, pver uint32, msgEnc wire.MessageEncoding) error {
	if input.NonWitnessTx != nil {
		txBuf := bytes.NewBuffer(make([]byte, 0, input.NonWitnessTx.SerializeSize()))
		err := input.NonWitnessTx.BtcEncode(txBuf, pver, msgEnc)
		if err != nil {
			return err
		}
		err = writeKeyValue(w, pver, string(InputNonWitnessTx), txBuf.Bytes())
		if err != nil {
			return err
		}
	} else if input.WitnessTxOut != nil {
		txOutWriter := bytes.NewBuffer(make([]byte, 0, input.WitnessTxOut.SerializeSize()))
		err := wire.WriteTxOut(txOutWriter, pver, 0, input.WitnessTxOut)
		if err != nil {
			return err
		}
		err = writeKeyValue(w, pver, string(InputWitnessTxOut), txOutWriter.Bytes())
		if err != nil {
			return err
		}
	}

	if input.PartialSig != nil {
		keys, sigs := input.PartialSig.Signatures()
		for i := 0; i < len(keys); i++ {
			err := writeKeyValue(w, pver, string(InputPartialSig)+string(keys[i].ScriptAddress()), sigs[i])
			if err != nil {
				return err
			}
		}
	}

	if input.SigHashType != nil {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], *input.SigHashType)
		err := writeKeyValue(w, pver, string(InputSigHashType), buf[:])
		if err != nil {
			return err
		}
	}

	if len(input.RedeemScript) > 0 {
		err := writeKeyValue(w, pver, string(InputRedeemScript), input.RedeemScript)
		if err != nil {
			return err
		}
	}

	if len(input.WitnessScript) > 0 {
		err := writeKeyValue(w, pver, string(InputWitnessScript), input.WitnessScript)
		if err != nil {
			return err
		}
	}

	if input.Bip32Derivation != nil {
		keys, keyInfoList := input.Bip32Derivation.Derivations()
		for i := 0; i < len(keys); i++ {
			keyBuf := bytes.NewBuffer(make([]byte, 0, keyInfoList[i].SerializeSize()))
			_, err := keyInfoList[i].Serialize(keyBuf)
			if err != nil {
				return err
			}
			err = writeKeyValue(w, pver, string(InputBip32Derivation)+string(keys[i].ScriptAddress()), keyBuf.Bytes())
			if err != nil {
				return err
			}
		}
	}

	if len(input.FinalScriptSig) > 0 {
		err := writeKeyValue(w, pver, string(InputFinalScriptSig), input.FinalScriptSig)
		if err != nil {
			return err
		}
	}

	if len(input.FinalWitness) > 0 {
		witBuf := bytes.NewBuffer(make([]byte, 0, input.FinalWitness.SerializeSize()))
		err := writeWitness(w, pver, input.FinalWitness)
		if err != nil {
			return err
		}
		err = writeKeyValue(w, pver, string(InputFinalWitness), witBuf.Bytes())
		if err != nil {
			return err
		}
	}

	if input.Unknown != nil {
		keys, values := input.Unknown.UnknownKVs()
		for i := 0; i < len(keys); i++ {
			err := writeKeyValue(w, pver, keys[i], values[i])
			if err != nil {
				return err
			}
		}
	}

	err := wire.WriteVarBytes(w, pver, nil)
	if err != nil {
		return err
	}

	return nil
}

func writeOutput(w *bytes.Buffer, o *TxOut, pver uint32) error {
	if len(o.RedeemScript) > 0 {
		err := writeKeyValue(w, pver, string(OutputRedeemScript), o.RedeemScript)
		if err != nil {
			return err
		}
	}

	if len(o.WitnessScript) > 0 {
		err := writeKeyValue(w, pver, string(OutputWitnessScript), o.WitnessScript)
		if err != nil {
			return err
		}
	}

	if o.Bip32Derivation != nil {
		keys, keyInfoList := o.Bip32Derivation.Derivations()
		for i := 0; i < len(keys); i++ {
			kbuf := bytes.NewBuffer(make([]byte, 0, keyInfoList[i].SerializeSize()))
			_, err := keyInfoList[i].Serialize(kbuf)
			if err != nil {
				return err
			}
			err = writeKeyValue(w, pver, string(OutputBip32Derivation)+string(keys[i].ScriptAddress()), kbuf.Bytes())
			if err != nil {
				return err
			}
		}
	}

	if o.Unknown != nil {
		keys, values := o.Unknown.UnknownKVs()
		for i := 0; i < len(keys); i++ {
			err := writeKeyValue(w, pver, keys[i], values[i])
			if err != nil {
				return err
			}
		}
	}

	err := wire.WriteVarInt(w, pver, 0)
	if err != nil {
		return err
	}

	return nil
}
