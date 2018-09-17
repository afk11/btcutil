package psbt

import (
	"testing"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)
func TestTxInValidate(t *testing.T) {
	t.Run("both witness and non-witness utxo info set", func(t *testing.T) {
		txin := &TxIn{
			NonWitnessTx: &wire.MsgTx{},
			WitnessTxOut: &wire.TxOut{0, nil},
		}
		err := txin.Validate()
		if err == nil {
			t.Fatal("error was expected")
		}
		if err.Error() != "both witness and non-witness utxo data set" {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	})
}
func TestTxValidate(t *testing.T) {
	t.Run("missing unsigned tx", func(t *testing.T) {
		tx := &Tx{}
		err := tx.Validate()
		if err == nil {
			t.Fatal("error was expected")
		}
		if err.Error() != "missing global unsigned tx" {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	})
	t.Run("invalid txin count", func(t *testing.T) {
		wireTx := wire.NewMsgTx(1)
		wireTx.TxIn = append(wireTx.TxIn, wire.NewTxIn(
			&wire.OutPoint{
				chainhash.Hash{},
				0xffffffff,
			},
			nil,
			nil,
		))
		tx := &Tx{
			GlobalUnsignedTx: wireTx,
		}
		err := tx.Validate()
		if err == nil {
			t.Fatal("error was expected")
		}
		if err.Error() != "invalid input count" {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	})
	t.Run("invalid txout count", func(t *testing.T) {
		wireTx := wire.NewMsgTx(1)
		wireTx.TxOut = append(wireTx.TxOut, wire.NewTxOut(1, nil))
		tx := &Tx{
			GlobalUnsignedTx: wireTx,
		}
		err := tx.Validate()
		if err == nil {
			t.Fatal("error was expected")
		}
		if err.Error() != "invalid output count" {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	})
	t.Run("non-empty txin scriptSig", func(t *testing.T) {
		wireTx := wire.NewMsgTx(1)
		wireTx.TxIn = append(wireTx.TxIn, wire.NewTxIn(
			&wire.OutPoint{
				chainhash.Hash{},
				0xffffffff,
			},
			[]byte(`\x00`),
			nil,
		))
		tx := &Tx{
			GlobalUnsignedTx: wireTx,
			TxIn: make([]*TxIn, 1),
		}
		tx.TxIn[0] = &TxIn{}
		err := tx.Validate()
		if err == nil {
			t.Fatal("error was expected")
		}
		if err.Error() != "scriptSig of global unsigned tx should be empty" {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	})
	t.Run("non-empty txin witness", func(t *testing.T) {
		wireTx := wire.NewMsgTx(1)
		wireTx.TxIn = append(wireTx.TxIn, wire.NewTxIn(
			&wire.OutPoint{
				chainhash.Hash{},
				0xffffffff,
			},
			nil,
			wire.TxWitness{[]byte{0x00}},
		))
		tx := &Tx{
			GlobalUnsignedTx: wireTx,
			TxIn: make([]*TxIn, 1),
		}
		tx.TxIn[0] = &TxIn{}
		err := tx.Validate()
		if err == nil {
			t.Fatal("error was expected")
		}
		if err.Error() != "witness of global unsigned tx should be empty" {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	})
}

func TestUnknownKVList(t *testing.T) {
	t.Run("no zero length keys", func(t *testing.T) {
		l := NewUnknownList()
		err := l.Append("", []byte{0x41})
		if err == nil {
			t.Fatalf("expected error")
		}
		if err.Error() != "key cannot be empty" {
			t.Fatalf("expected error")
		}
	})
	t.Run("no duplicates", func(t *testing.T) {
		l := NewUnknownList()
		err := l.Append("a", []byte{0x41})
		if err != nil {
			t.Fatalf("unexpected error")
		}
		err = l.Append("a", []byte{0x41})
		if err == nil {
			t.Fatalf("error expected")
		}
		if err.Error() != "duplicate unknown key" {
			t.Fatalf("expected error")
		}
	})
	t.Run("append and list", func(t *testing.T) {
		l := NewUnknownList()
		if len(l.dmap) != 0 || len(l.list) != 0 {
			t.Fatal("list should be empty")
		}

		k, v := l.UnknownKVs()
		if len(k) != 0 || len(v) != 0 {
			t.Fatal("list should be empty")
		}

		key := "a"
		err := l.Append(key, []byte{0x41})
		if err != nil {
			t.Fatalf("unexpected error %s", err.Error())
		}
		if len(l.dmap) != 1 || len(l.list) != 1 {
			t.Fatal("list should have one value")
		}
		k, v = l.UnknownKVs()
		if len(k) != 1 || len(v) != 1 {
			t.Fatal("list should have one value")
		}
		_, exists := l.dmap[key]
		if !exists {
			t.Fatal("missing our tests key")
		}

		key = "b"
		err = l.Append(key, []byte{0x42})
		if err != nil {
			t.Fatalf("unexpected error %s", err.Error())
		}
		if len(l.dmap) != 2 || len(l.list) != 2 {
			t.Fatal("list should have 2 values")
		}
		k, v = l.UnknownKVs()
		if len(k) != 2 || len(v) != 2 {
			t.Fatal("list should have 1 values")
		}
		_, exists = l.dmap[key]
		if !exists {
			t.Fatal("missing our tests key")
		}
	})
}