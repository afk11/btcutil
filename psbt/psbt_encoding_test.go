package psbt

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/hdkeychain"
)

func TestParsePSBT(t *testing.T) {
	t.Run("detects invalid magic", func(t *testing.T) {
		raw := []byte("psbt\x00")
		_, err := ParsePSBT(&chaincfg.MainNetParams, bytes.NewReader(raw), 0, wire.WitnessEncoding)
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	for i := 0; i < len(validFixtures); i++ {
		t.Run(fmt.Sprintf("valid %d", i), func(t *testing.T) {
			fixture := validFixtures[i]
			psbtRaw, err := hex.DecodeString(fixture.hex)
			if err != nil {
				t.Fatalf("failed to parse hex fixture")
			}

			pver := uint32(0)
			psbt, err := ParsePSBT(&chaincfg.MainNetParams, bytes.NewReader(psbtRaw), pver, wire.WitnessEncoding)
			if err != nil {
				t.Fatalf("failed parsing psbt: %s", err.Error())
			}
			raw, err := psbt.Encode(pver, wire.WitnessEncoding)
			if err != nil {
				t.Fatalf("unexpected failure")
			}
			if !bytes.Equal(raw, psbtRaw) {
				t.Fatalf("encoding should match\n%s\n%s", fixture.hex, hex.EncodeToString(raw))
			}
		})
	}
	for i := 0; i < len(invalidFixtures); i++ {
		t.Run(fmt.Sprintf("invalid %d", i), func(t *testing.T) {
			fixture := invalidFixtures[i]
			psbtRaw, err := hex.DecodeString(fixture.hex)
			if err != nil {
				t.Fatalf("failed to parse hex fixture")
			}
			_, err = ParsePSBT(&chaincfg.MainNetParams, bytes.NewReader(psbtRaw), 0, wire.WitnessEncoding)
			if err == nil {
				t.Fatalf("expected failure")
			}
		})
	}
}

func TestParsePSBTDetails(t *testing.T) {
	fixtureMap := make(map[string]psbtFixture, len(validFixtures))
	for _, fixture := range validFixtures {
		fixtureMap[fixture.comment] = fixture
	}

	fixture2Comment := "PSBT with one P2PKH input and one P2SH-P2WPKH input. First input is signed and finalized. Outputs are empty"
	fixture2, exists := fixtureMap[fixture2Comment]
	if !exists {
		t.Fatalf("missing expected PSBT fixture: %s", fixture2Comment)
	}

	t.Run("details 2", func(t *testing.T) {
		raw, err := hex.DecodeString(fixture2.hex)
		if err != nil {
			t.Fatal(t, "failed parsing hex fixture")
		}
		psbt, err := ParsePSBT(&chaincfg.MainNetParams, bytes.NewReader(raw), 0, wire.WitnessEncoding)
		if err != nil {
			t.Fatal(t, "Unexpected failure")
		}
		if psbt.Unknown != nil {
			t.Fatal(t, "no global unknowns expected")
		}

		globalTxID := psbt.GlobalUnsignedTx.TxHash()
		expectedTxID := "fed6cd1fde4db4e13e7e800317e37f9cbd75ec364389670eeff80da993c7e560"
		if expectedTxID != globalTxID.String() {
			t.Fatal(t, "global txid doesn't match expected")
		}
		if len(psbt.TxIn) != 2 {
			t.Fatal(t, "expected 2 inputs")
		}

		in0 := psbt.TxIn[0]
		if in0.FinalScriptSig == nil {
			t.Fatal(t, "txin 0 expected scriptsig")
		}

		if "47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292" != hex.EncodeToString(in0.FinalScriptSig) {
			t.Fatal(t, "txin 0 wrong scriptsig")
		}

		in1 := psbt.TxIn[1]
		if in1.WitnessTxOut == nil {
			t.Fatal(t, "txin 1 expected witness txout")
		}
		if 100000000 != in1.WitnessTxOut.Value {
			t.Fatal(t, "txin 1 incorrect witness txout value")
		}
		if "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787" != hex.EncodeToString(in1.WitnessTxOut.PkScript) {
			t.Fatal(t, "txin 1 incorrect witness txout script")
		}
		if in1.RedeemScript == nil {
			t.Fatal(t, "txin 1 expected redeemscript")
		}
		if "001485d13537f2e265405a34dbafa9e3dda01fb82308" != hex.EncodeToString(in1.RedeemScript) {
			t.Fatal(t, "txin 1 incorrect witness txout script")
		}
		if len(psbt.TxOut) != 2 {
			t.Fatal(t, "expected 2 outputs")
		}
	})

	fixture3Comment := "PSBT with one P2PKH input which has a non-final scriptSig and has a sighash type specified. Outputs are empty"
	fixture3, exists := fixtureMap[fixture3Comment]
	if !exists {
		t.Fatalf("missing expected PSBT fixture: %s", fixture3Comment)
	}

	t.Run("details 3", func(t *testing.T) {
		raw, err := hex.DecodeString(fixture3.hex)
		if err != nil {
			t.Fatal(t, "failed parsing hex fixture")
		}
		psbt, err := ParsePSBT(&chaincfg.MainNetParams, bytes.NewReader(raw), 0, wire.WitnessEncoding)
		if err != nil {
			t.Fatal(t, "Unexpected failure")
		}
		if psbt.Unknown != nil {
			t.Fatal(t, "no global unknowns expected")
		}

		globalTxID := psbt.GlobalUnsignedTx.TxHash()
		expectedTxID := "af2cac1e0e33d896d9d0751d66fcb2fa54b737c7a13199281fb57e4f497bb652"
		if expectedTxID != globalTxID.String() {
			t.Fatal(t, "global txid doesn't match expected")
		}
		if len(psbt.TxIn) != 1 {
			t.Fatal(t, "expected 1 input")
		}

		in0 := psbt.TxIn[0]
		if in0.NonWitnessTx == nil {
			t.Fatal(t, "txin 0 expected nonwitness utxo")
		}

		firstTxID := in0.NonWitnessTx.TxHash()
		expectedFirstTxID := "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
		if expectedFirstTxID != firstTxID.String() {
			t.Fatal(t, "txin 0 nonwitness txid doesn't match expected")
		}

		if in0.SigHashType == nil {
			t.Fatal(t, "txin 0 expected sighash type")
		}

		if len(psbt.TxOut) != 2 {
			t.Fatal(t, "expected 2 outputs")
		}

		if *in0.SigHashType != uint32(txscript.SigHashAll) {
			t.Fatal(t, "wrong sighash type %d %d", *in0.SigHashType, uint32(txscript.SigHashAll))
		}
	})
	fixture4Comment := "PSBT with one P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs. P2SH-P2WPKH input's redeemScript is available. Outputs filled."
	fixture4, exists := fixtureMap[fixture4Comment]
	if !exists {
		t.Fatalf("missing expected PSBT fixture: %s", fixture4Comment)
	}

	t.Run("details 4", func(t *testing.T) {
		raw, err := hex.DecodeString(fixture4.hex)
		if err != nil {
			t.Fatal(t, "failed parsing hex fixture")
		}
		psbt, err := ParsePSBT(&chaincfg.MainNetParams, bytes.NewReader(raw), 0, wire.WitnessEncoding)
		if err != nil {
			t.Fatal(t, "Unexpected failure")
		}
		if psbt.Unknown != nil {
			t.Fatal(t, "no global unknowns expected")
		}

		globalTxID := psbt.GlobalUnsignedTx.TxHash()
		expectedTxID := "fed6cd1fde4db4e13e7e800317e37f9cbd75ec364389670eeff80da993c7e560"
		if expectedTxID != globalTxID.String() {
			t.Fatal(t, "global txid doesn't match expected")
		}
		if len(psbt.TxIn) != 2 {
			t.Fatal(t, "expected 2 inputs")
		}

		in0 := psbt.TxIn[0]
		if in0.NonWitnessTx == nil {
			t.Fatal(t, "txin 0 expected nonwitness utxo")
		}

		firstTxID := in0.NonWitnessTx.TxHash()
		expectedFirstTxID := "e47b5b7a879f13a8213815cf3dc3f5b35af1e217f412829bc4f75a8ca04909ab"
		if expectedFirstTxID != firstTxID.String() {
			t.Fatal(t, "txin 1 nonwitness txid doesn't match expected")
		}

		in1 := psbt.TxIn[1]
		if in1.WitnessTxOut == nil {
			t.Fatal(t, "txin 1 expected witness txout")
		}
		if 100000000 != in1.WitnessTxOut.Value {
			t.Fatal(t, "txin 1 wrong value")
		}
		if "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787" != hex.EncodeToString(in1.WitnessTxOut.PkScript) {
			t.Fatal(t, "txin 1 wrong value")
		}
		if in1.RedeemScript == nil {
			t.Fatal(t, "txin 1 expected redeem script")
		}
		if "001485d13537f2e265405a34dbafa9e3dda01fb82308" != hex.EncodeToString(in1.RedeemScript) {
			t.Fatal(t, "txin 1 wrong redeem script")
		}
		if len(psbt.TxOut) != 2 {
			t.Fatal(t, "expected 2 outputs")
		}

		out0 := psbt.TxOut[0]
		if out0.Bip32Derivation == nil {
			t.Fatal(t, "out0 expected bip32 derivation")
		}
		dKeys, derivValue := out0.Bip32Derivation.Derivations()
		if len(dKeys) != 1 || len(derivValue) != 1 {
			t.Fatal(t, "expected 1 derivation")
		}
		if derivValue[0].MasterKeyID != 0xb4a6ba67 {
			t.Fatal(t, "wrong master key id for deriv 0")
		}
		if len(derivValue[0].Path) != 3 {
			t.Fatal(t, "wrong path length for deriv 0")
		}
		if derivValue[0].Path[0] != hdkeychain.HardenedKeyStart+0 {
			t.Fatal(t, "wrong path part 0 for deriv 0")
		}
		if derivValue[0].Path[1] != hdkeychain.HardenedKeyStart+0 {
			t.Fatal(t, "wrong path part 1 for deriv 0")
		}
		if derivValue[0].Path[2] != hdkeychain.HardenedKeyStart+2 {
			t.Fatal(t, "wrong path part 2 for deriv 0")
		}
		if "02ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e99" != hex.EncodeToString(dKeys[0].ScriptAddress()) {
			t.Fatal(t, "wrong public key for derivation 0")
		}

		out1 := psbt.TxOut[1]
		if out1.Bip32Derivation == nil {
			t.Fatal(t, "out1 expected bip32 derivation")
		}
		dKeys, derivValue = out1.Bip32Derivation.Derivations()
		if len(dKeys) != 1 || len(derivValue) != 1 {
			t.Fatal(t, "expected 1 derivation")
		}
		if derivValue[0].MasterKeyID != 0xb4a6ba67 {
			t.Fatal(t, "wrong master key id for deriv 1")
		}
		if len(derivValue[0].Path) != 3 {
			t.Fatal(t, "wrong path length for deriv 1")
		}
		if derivValue[0].Path[0] != hdkeychain.HardenedKeyStart+0 {
			t.Fatal(t, "wrong path part 0 for deriv 1")
		}
		if derivValue[0].Path[1] != hdkeychain.HardenedKeyStart+1 {
			t.Fatal(t, "wrong path part 1 for deriv 1")
		}
		if derivValue[0].Path[2] != hdkeychain.HardenedKeyStart+2 {
			t.Fatal(t, "wrong path part 2 for deriv 1")
		}
		if "0394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d05" != hex.EncodeToString(dKeys[0].ScriptAddress()) {
			t.Fatal(t, "wrong public key for derivation 1")
		}
	})

	fixture5Comment := "PSBT with one P2SH-P2WSH input of a 2-of-2 multisig, redeemScript, witnessScript, and keypaths are available. Contains one signature."
	fixture5, exists := fixtureMap[fixture5Comment]
	if !exists {
		t.Fatalf("missing expected PSBT fixture: %s", fixture5Comment)
	}
	t.Run("details 5", func(t *testing.T) {
		raw, err := hex.DecodeString(fixture5.hex)
		if err != nil {
			t.Fatal(t, "failed parsing hex fixture")
		}
		psbt, err := ParsePSBT(&chaincfg.MainNetParams, bytes.NewReader(raw), 0, wire.WitnessEncoding)
		if err != nil {
			t.Fatal(t, "Unexpected failure")
		}
		if psbt.Unknown != nil {
			t.Fatal(t, "no global unknowns expected")
		}

		globalTxID := psbt.GlobalUnsignedTx.TxHash()
		expectedTxID := "b4ca8f48572bf08354f8302adfbd9e5c2fc2a52731de5401a39aa048f68c9c21"
		if expectedTxID != globalTxID.String() {
			t.Fatal(t, "global txid doesn't match expected")
		}
		if len(psbt.TxIn) != 1 {
			t.Fatal(t, "expected one input")
		}
		if len(psbt.TxOut) != 1 {
			t.Fatal(t, "expected one output")
		}

		out := psbt.TxOut[0]
		if out.WitnessScript != nil {
			t.Fatal(t, "output witness script unexpected")
		}
		if out.RedeemScript != nil {
			t.Fatal(t, "output redeem script unexpected")
		}
		if out.Bip32Derivation != nil {
			t.Fatal(t, "output bip32 derivations unexpected")
		}
		if out.Unknown != nil {
			t.Fatal(t, "output unknowns")
		}

		in := psbt.TxIn[0]
		if in.NonWitnessTx != nil {
			t.Fatal(t, "txin nonwitnesstx unexpected")
		}
		if in.WitnessTxOut == nil {
			t.Fatal(t, "expected txin witness txOut")
		}
		if 199909013 != in.WitnessTxOut.Value {
			t.Fatal(t, "wrong value for witness txOut")
		}
		if "a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87" != hex.EncodeToString(in.WitnessTxOut.PkScript) {
			t.Fatal(t, "wrong script for witness txOut")
		}

		if in.WitnessScript == nil {
			t.Fatal(t, "expected witness script")
		}
		if "522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae" != hex.EncodeToString(in.WitnessScript) {
			t.Fatal(t, "wrong script for witness txOut")
		}

		if in.RedeemScript == nil {
			t.Fatal(t, "expected witness script")
		}
		if "0020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681" != hex.EncodeToString(in.RedeemScript) {
			t.Fatal(t, "wrong script for witness txOut")
		}

		if in.Bip32Derivation == nil {
			t.Fatal(t, "expected bip32 derivations")
		}

		dKeys, derivValue := in.Bip32Derivation.Derivations()
		if len(dKeys) != 2 || len(derivValue) != 2 {
			t.Fatal(t, "expected 2 bip32 derivations")
		}

		if "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46" != hex.EncodeToString(dKeys[0].ScriptAddress()) {
			t.Fatal(t, "wrong public key for derivation 0")
		}
		if "03de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd" != hex.EncodeToString(dKeys[1].ScriptAddress()) {
			t.Fatal(t, "wrong public key for derivation 1")
		}

		if derivValue[0].MasterKeyID != 0xb4a6ba67 {
			t.Fatal(t, "wrong master key id for deriv 0")
		}
		if len(derivValue[0].Path) != 3 {
			t.Fatal(t, "wrong path length for deriv 0")
		}
		if derivValue[0].Path[0] != hdkeychain.HardenedKeyStart+0 {
			t.Fatal(t, "wrong path part 0 for deriv 0")
		}
		if derivValue[0].Path[1] != hdkeychain.HardenedKeyStart+0 {
			t.Fatal(t, "wrong path part 1 for deriv 0")
		}
		if derivValue[0].Path[2] != hdkeychain.HardenedKeyStart+4 {
			t.Fatal(t, "wrong path part 2 for deriv 0")
		}

		if derivValue[1].MasterKeyID != 0xb4a6ba67 {
			t.Fatal(t, "wrong master key id for deriv 1")
		}
		if len(derivValue[1].Path) != 3 {
			t.Fatal(t, "wrong path length for deriv 1")
		}
		if derivValue[1].Path[0] != hdkeychain.HardenedKeyStart+0 {
			t.Fatal(t, "wrong path part 0 for deriv 1")
		}
		if derivValue[1].Path[1] != hdkeychain.HardenedKeyStart+0 {
			t.Fatal(t, "wrong path part 1 for deriv 1")
		}
		if derivValue[1].Path[2] != hdkeychain.HardenedKeyStart+5 {
			t.Fatal(t, "wrong path part 2 for deriv 1")
		}

		if in.PartialSig == nil {
			t.Fatal(t, "expected partial sig")
		}
		sKeys, sigValues := in.PartialSig.Signatures()
		if len(sKeys) != 1 || len(sigValues) != 1 {
			t.Fatal(t, "expected 1 signature")
		}
		if "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46" != hex.EncodeToString(sKeys[0].ScriptAddress()) {
			t.Fatal(t, "wrong public key for signature 0")
		}
		if "304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01" != hex.EncodeToString(sigValues[0]) {
			t.Fatal(t, "wrong partial signature for sig 0")
		}
	})

	fixture6Comment := "PSBT with unknown types in the inputs."
	fixture6, exists := fixtureMap[fixture6Comment]
	if !exists {
		t.Fatalf("missing expected PSBT fixture: %s", fixture6Comment)
	}
	t.Run("details 6", func(t *testing.T) {
		raw, err := hex.DecodeString(fixture6.hex)
		if err != nil {
			t.Fatal(t, "failed parsing hex fixture")
		}
		psbt, err := ParsePSBT(&chaincfg.MainNetParams, bytes.NewReader(raw), 0, wire.WitnessEncoding)
		if err != nil {
			t.Fatal(t, "Unexpected failure")
		}
		if psbt.Unknown != nil {
			t.Fatal(t, "no global unknowns expected")
		}
		if len(psbt.TxIn) != 1 {
			t.Fatal(t, "expected one input")
		}
		if len(psbt.TxOut) != 1 {
			t.Fatal(t, "expected one output")
		}
		globalTxID := psbt.GlobalUnsignedTx.TxHash()
		expectedTxID := "75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115"
		if expectedTxID != globalTxID.String() {
			t.Fatal(t, "global txid doesn't match expected")
		}
		in := psbt.TxIn[0]
		if in.Unknown == nil {
			t.Fatal(t, "expected unknown map")
		}
		uKeys, uValues := in.Unknown.UnknownKVs()
		if len(uKeys) != 1 || len(uValues) != 1 {
			t.Fatal(t, "expected 1 unknown key/value")
		}
		expectedKey := "0f010203040506070809"
		expectedValue := "0102030405060708090a0b0c0d0e0f"
		if expectedKey != hex.EncodeToString([]byte(uKeys[0])) {
			t.Fatal(t, "wrong unknown key")
		}
		if expectedValue != hex.EncodeToString(uValues[0]) {
			t.Fatal(t, "wrong unknown value")
		}
	})
}
