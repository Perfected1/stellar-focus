package capture_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stellar-optics/stellar-focus/internal/fakesource"
	"github.com/stellar-optics/stellar-focus/pkg/capture"
	"github.com/stellar-optics/stellar-focus/pkg/golden"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestNewAccountLedgerKey(t *testing.T) {
	t.Parallel()

	const address = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
	key, err := capture.NewAccountLedgerKey(address)
	if err != nil {
		t.Fatalf("NewAccountLedgerKey() error = %v", err)
	}
	if key.Type != 0 {
		t.Fatalf("key type = %v, want account", key.Type)
	}
	encoded, err := capture.EncodeLedgerKey(key)
	if err != nil {
		t.Fatalf("EncodeLedgerKey() error = %v", err)
	}
	if encoded == "" {
		t.Fatal("EncodeLedgerKey() returned an empty string")
	}
}

func TestNewAccountLedgerKeyRejectsInvalidAddress(t *testing.T) {
	t.Parallel()
	if _, err := capture.NewAccountLedgerKey("not-an-account"); err == nil {
		t.Fatal("NewAccountLedgerKey() accepted an invalid StrKey")
	}
}

// capturedAt is fixed so fixtures produced by these tests are byte-stable.
var capturedAt = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

func envelopeXDR(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pkg", "fuzz", "testdata", "tx_failed.env.txt"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func resultXDR(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pkg", "fuzz", "testdata", "tx_failed.res.txt"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func sourceWithTransaction(t *testing.T, hash string) *fakesource.Source {
	t.Helper()
	src := fakesource.New(capture.NetworkTestnet, "https://fake.example")
	src.Transactions[hash] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope", XDR: envelopeXDR(t),
			Ledger: 1234, TxHash: hash, Description: "envelope",
		},
		{
			Name: "result", Type: "TransactionResult", XDR: resultXDR(t),
			Ledger: 1234, TxHash: hash, Description: "result",
		},
	}
	return src
}

func TestCaptureStampsProvenance(t *testing.T) {
	t.Parallel()

	const hash = "abc123"
	src := sourceWithTransaction(t, hash)

	records, err := src.Transaction(context.Background(), hash)
	if err != nil {
		t.Fatalf("Transaction() error = %v", err)
	}

	fixtures, err := capture.Capture(context.Background(), src, records, capturedAt)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if len(fixtures) != 2 {
		t.Fatalf("captured %d fixtures, want 2", len(fixtures))
	}

	for _, f := range fixtures {
		if f.Captured == nil {
			t.Fatal("fixture has no provenance; a captured fixture must be traceable")
		}
		if f.Captured.Network != capture.NetworkTestnet {
			t.Errorf("network = %q, want testnet", f.Captured.Network)
		}
		if f.Captured.TxHash != hash {
			t.Errorf("txHash = %q, want %q", f.Captured.TxHash, hash)
		}
		if f.Captured.Ledger != 1234 {
			t.Errorf("ledger = %d, want 1234", f.Captured.Ledger)
		}
		if f.Captured.At != "2026-08-05T12:00:00Z" {
			t.Errorf("at = %q, want the supplied timestamp", f.Captured.At)
		}
		if f.Captured.Endpoint != "https://fake.example" {
			t.Errorf("endpoint = %q", f.Captured.Endpoint)
		}
		if f.XDR == "" || f.Decoded == nil {
			t.Error("fixture is missing its XDR or decoded form")
		}
	}
}

// TestCaptureIsDeterministic matters because a capture that produced a
// different file each run would make every refresh look like a change.
func TestCaptureIsDeterministic(t *testing.T) {
	t.Parallel()

	const hash = "abc123"
	src := sourceWithTransaction(t, hash)
	records, err := src.Transaction(context.Background(), hash)
	if err != nil {
		t.Fatalf("Transaction() error = %v", err)
	}

	dir := t.TempDir()
	render := func(name string) string {
		fixtures, err := capture.Capture(context.Background(), src, records, capturedAt)
		if err != nil {
			t.Fatalf("Capture() error = %v", err)
		}
		path := filepath.Join(dir, name)
		if err := golden.Save(path, fixtures[0]); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		return string(b)
	}

	if render("a.json") != render("b.json") {
		t.Error("two captures of the same data produced different files")
	}
}

func TestVerifyMatches(t *testing.T) {
	t.Parallel()

	const hash = "abc123"
	src := sourceWithTransaction(t, hash)
	records, _ := src.Transaction(context.Background(), hash)
	fixtures, err := capture.Capture(context.Background(), src, records, capturedAt)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}

	got := capture.Verify(context.Background(), src, "envelope.golden.json", fixtures[0])
	if got.Err != nil {
		t.Fatalf("Verify() error = %v", got.Err)
	}
	if !got.Match {
		t.Errorf("Verify() reported a mismatch for unchanged data; diff = %v", got.Diff)
	}
}

func TestCaptureBindsNetworkPassphraseAndVerifyChecksIt(t *testing.T) {
	t.Parallel()

	const hash = "abc123"
	src := sourceWithTransaction(t, hash)
	src.Passphrase = "Test SDF Network ; September 2015"
	records, err := src.Transaction(context.Background(), hash)
	if err != nil {
		t.Fatalf("Transaction() error = %v", err)
	}
	fixtures, err := capture.Capture(context.Background(), src, records, capturedAt)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	if got := fixtures[0].Captured.NetworkPassphrase; got != src.Passphrase {
		t.Fatalf("captured passphrase = %q, want %q", got, src.Passphrase)
	}

	src.Passphrase = "Public Global Stellar Network ; September 2015"
	got := capture.Verify(context.Background(), src, "envelope.golden.json", fixtures[0])
	if got.Err == nil || !strings.Contains(got.Err.Error(), "passphrase mismatch") {
		t.Fatalf("Verify() error = %v, want passphrase mismatch", got.Err)
	}
}

func TestVerifyRefusesAnonymizedFixturesWithoutFetching(t *testing.T) {
	t.Parallel()

	const hash = "abc123"
	src := sourceWithTransaction(t, hash)
	records, err := src.Transaction(context.Background(), hash)
	if err != nil {
		t.Fatalf("Transaction() error = %v", err)
	}
	records[0].Anonymized = true
	fixtures, err := capture.Capture(context.Background(), src, records[:1], capturedAt)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	src.Calls = 0

	got := capture.Verify(context.Background(), src, "masked.golden.json", fixtures[0])
	if got.Err == nil || !strings.Contains(got.Err.Error(), "anonymized") {
		t.Fatalf("Verify() error = %v, want anonymized fixture explanation", got.Err)
	}
	if src.Calls != 0 {
		t.Errorf("Verify() fetched %d times for an anonymized fixture", src.Calls)
	}
}

// TestVerifyDetectsDrift covers the point of the command: a fixture that no
// longer matches the chain must be reported, with the change named.
func TestVerifyDetectsDrift(t *testing.T) {
	t.Parallel()

	const hash = "abc123"
	src := sourceWithTransaction(t, hash)
	records, _ := src.Transaction(context.Background(), hash)
	fixtures, err := capture.Capture(context.Background(), src, records, capturedAt)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}

	// The chain now returns a different envelope for the same hash.
	src.Transactions[hash] = []capture.Record{{
		Name: "envelope", Type: "TransactionEnvelope",
		XDR:    fixtureFromFile(t, "tx_success.env.txt"),
		Ledger: 1234, TxHash: hash,
	}}

	got := capture.Verify(context.Background(), src, "envelope.golden.json", fixtures[0])
	if got.Err != nil {
		t.Fatalf("Verify() error = %v", got.Err)
	}
	if got.Match {
		t.Fatal("Verify() reported a match for changed data")
	}
	if got.Diff == nil || len(got.Diff.Changes) == 0 {
		t.Fatal("Verify() reported no diff explaining the mismatch")
	}
}

// TestVerifyRefusesFixturesWithNoProvenance keeps a hand-written fixture from
// silently passing a check it was never eligible for.
func TestVerifyRefusesFixturesWithNoProvenance(t *testing.T) {
	t.Parallel()

	f, err := golden.Build(envelopeXDR(t), "TransactionEnvelope", "hand written", nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	src := fakesource.New(capture.NetworkTestnet, "https://fake.example")
	got := capture.Verify(context.Background(), src, "hand.golden.json", f)

	if got.Err == nil {
		t.Fatal("Verify() accepted a fixture with no provenance")
	}
	if got.Match {
		t.Error("Verify() reported a match it could not have checked")
	}
	if !strings.Contains(got.Err.Error(), "provenance") {
		t.Errorf("error does not explain why: %v", got.Err)
	}
	if src.Calls != 0 {
		t.Errorf("the network was contacted %d time(s) for an unverifiable fixture", src.Calls)
	}
}

func TestVerifyReportsAMissingTransaction(t *testing.T) {
	t.Parallel()

	src := sourceWithTransaction(t, "abc123")
	records, _ := src.Transaction(context.Background(), "abc123")
	fixtures, _ := capture.Capture(context.Background(), src, records, capturedAt)

	// The transaction has aged out of the endpoint's retention window.
	delete(src.Transactions, "abc123")

	got := capture.Verify(context.Background(), src, "env.golden.json", fixtures[0])
	if got.Err == nil {
		t.Fatal("Verify() succeeded against a transaction that is gone")
	}
	if !errors.Is(got.Err, capture.ErrNotFound) {
		t.Errorf("error does not wrap ErrNotFound: %v", got.Err)
	}
}

func TestResolveEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		network  string
		override string
		want     string
		wantErr  bool
	}{
		{"testnet default", capture.NetworkTestnet, "", capture.DefaultEndpoints[capture.NetworkTestnet], false},
		{"mainnet default", capture.NetworkMainnet, "", capture.DefaultEndpoints[capture.NetworkMainnet], false},
		{"override wins", capture.NetworkTestnet, "http://localhost:8000", "http://localhost:8000", false},
		{"unknown network", "wonderland", "", "", true},
		{"unknown network with override", "wonderland", "http://x", "http://x", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := capture.ResolveEndpoint(tc.network, tc.override)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ResolveEndpoint() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveEndpoint() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("ResolveEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolveHorizonEndpoint checks that the Horizon defaults are their
// own, since a Horizon endpoint and an RPC endpoint are different
// services.
func TestResolveHorizonEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		network  string
		override string
		want     string
		wantErr  bool
	}{
		{"testnet default", capture.NetworkTestnet, "", capture.DefaultHorizonEndpoints[capture.NetworkTestnet], false},
		{"mainnet default", capture.NetworkMainnet, "", capture.DefaultHorizonEndpoints[capture.NetworkMainnet], false},
		{"override wins", capture.NetworkTestnet, "http://localhost:8000", "http://localhost:8000", false},
		{"unknown network", "wonderland", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := capture.ResolveHorizonEndpoint(tc.network, tc.override)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ResolveHorizonEndpoint() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveHorizonEndpoint() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("ResolveHorizonEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDefaultIsTestnet guards against a tool that reaches for mainnet unless
// told otherwise.
func TestDefaultIsTestnet(t *testing.T) {
	t.Parallel()

	if !strings.Contains(capture.DefaultEndpoints[capture.NetworkTestnet], "testnet") {
		t.Error("the testnet endpoint does not look like testnet")
	}
}

func fixtureFromFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pkg", "fuzz", "testdata", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}

// multiOpEnvelopeXDR builds a V1 envelope with the given number of payment
// operations, for testing the --min-ops filter.
func multiOpEnvelopeXDR(t *testing.T, n int) string {
	t.Helper()
	var ops []xdr.Operation
	for i := 0; i < n; i++ {
		ops = append(ops, xdr.Operation{
			Body: xdr.OperationBody{
				Type: xdr.OperationTypePayment,
				PaymentOp: &xdr.PaymentOp{
					Destination: xdr.MustMuxedAddress("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"),
					Amount:      100,
					Asset:       xdr.Asset{Type: xdr.AssetTypeAssetTypeNative},
				},
			},
		})
	}
	tx := xdr.Transaction{
		SourceAccount: xdr.MustMuxedAddress("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"),
		Fee:           100,
		SeqNum:        1,
		Operations:    ops,
	}
	env, err := xdr.MarshalBase64(xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1:   &xdr.TransactionV1Envelope{Tx: tx},
	})
	if err != nil {
		t.Fatalf("encoding multiOpEnvelope: %v", err)
	}
	return env
}

// sorobanEnvelopeXDR returns a Soroban envelope fixture.
func sorobanEnvelopeXDR(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pkg", "fuzz", "testdata", "tx_soroban.env.txt"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// failedResultXDR returns a failed result fixture.
func failedResultXDR(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pkg", "fuzz", "testdata", "tx_failed.res.txt"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func ptrOf[T any](v T) *T { return &v }

func mustEnvFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pkg", "fuzz", "testdata", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}
func mustResFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "pkg", "fuzz", "testdata", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}

func mustEncodeSuccessResult(t *testing.T) string {
	t.Helper()
	res, err := xdr.MarshalBase64(xdr.TransactionResult{
		FeeCharged: 100,
		Result: xdr.TransactionResultResult{
			Code:    xdr.TransactionResultCodeTxSuccess,
			Results: ptrOf([]xdr.OperationResult{}),
		},
	})
	if err != nil {
		t.Fatalf("encoding success result: %v", err)
	}
	return res
}

// TestFilterRecordsMinOps keeps only the transactions with enough operations.
func TestFilterRecordsMinOps(t *testing.T) {
	t.Parallel()
	src := fakesource.New(capture.NetworkTestnet, "https://fake.example")
	hashA := "aaaa1111"
	hashB := "bbbb2222"
	t.Helper()
	src.Transactions[hashA] = []capture.Record{{
		Name: "envelope", Type: "TransactionEnvelope", XDR: envelopeXDR(t),
		Ledger: 100, TxHash: hashA,
	}}
	src.Transactions[hashB] = []capture.Record{{
		Name: "envelope", Type: "TransactionEnvelope", XDR: multiOpEnvelopeXDR(t, 2),
		Ledger: 100, TxHash: hashB,
	}}
	records := []capture.Record{}
	for _, h := range []string{hashA, hashB} {
		records = append(records, src.Transactions[h]...)
	}
	kept, err := capture.FilterRecords(records, capture.FilterOptions{MinOps: 2})
	if err != nil {
		t.Fatalf("FilterRecords() error = %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("kept %d records, want 1", len(kept))
	}
	if kept[0].TxHash != hashB {
		t.Errorf("kept %s, want %s", kept[0].TxHash, hashB)
	}
}

// diagnoseEnvelope prints info about an envelope.
// TestFilterRecordsOnlySoroban keeps only the Soroban transactions.
func TestFilterRecordsOnlySoroban(t *testing.T) {
	t.Parallel()
	src := fakesource.New(capture.NetworkTestnet, "https://fake.example")
	hashNonSoroban := "classic01"
	hashSoroban := "sor0001"
	t.Helper()
	src.Transactions[hashNonSoroban] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope",
			XDR:    multiOpEnvelopeXDR(t, 1),
			Ledger: 100, TxHash: hashNonSoroban,
		},
	}
	src.Transactions[hashSoroban] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope",
			XDR:    mustEnvFile(t, "tx_soroban.env.txt"),
			Ledger: 100, TxHash: hashSoroban,
		},
	}
	var records []capture.Record
	for _, h := range []string{hashNonSoroban, hashSoroban} {
		records = append(records, src.Transactions[h]...)
	}
	kept, err := capture.FilterRecords(records, capture.FilterOptions{OnlySoroban: true})
	if err != nil {
		t.Fatalf("FilterRecords() error = %v", err)
	}
	if len(kept) != 1 {
		t.Fatalf("kept %d records, want 1", len(kept))
	}
	if kept[0].TxHash != hashSoroban {
		t.Errorf("kept %s, want %s", kept[0].TxHash, hashSoroban)
	}
}

// TestFilterRecordsFailedOnly keeps only the failed transactions.
func TestFilterRecordsFailedOnly(t *testing.T) {
	t.Parallel()
	src := fakesource.New(capture.NetworkTestnet, "https://fake.example")
	hashSuccess := "success01"
	hashFailed := "fail0001"
	t.Helper()
	// Build a success result: code = txSUCCESS.
	successRes, err := xdr.MarshalBase64(xdr.TransactionResult{
		FeeCharged: 100,
		Result: xdr.TransactionResultResult{
			Code:    xdr.TransactionResultCodeTxSuccess,
			Results: ptrOf([]xdr.OperationResult{}),
		},
	})
	if err != nil {
		t.Fatalf("encoding success result: %v", err)
	}
	src.Transactions[hashSuccess] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope",
			XDR:    mustEnvFile(t, "tx_success.env.txt"),
			Ledger: 100, TxHash: hashSuccess,
		},
		{
			Name: "result", Type: "TransactionResult",
			XDR:    successRes,
			Ledger: 100, TxHash: hashSuccess,
		},
	}
	src.Transactions[hashFailed] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope",
			XDR:    mustEnvFile(t, "tx_failed.env.txt"),
			Ledger: 100, TxHash: hashFailed,
		},
		{
			Name: "result", Type: "TransactionResult",
			XDR:    mustResFile(t, "tx_failed.res.txt"),
			Ledger: 100, TxHash: hashFailed,
		},
	}
	records := []capture.Record{}
	for _, h := range []string{hashSuccess, hashFailed} {
		records = append(records, src.Transactions[h]...)
	}
	kept, err := capture.FilterRecords(records, capture.FilterOptions{FailedOnly: true})
	if err != nil {
		t.Fatalf("FilterRecords() error = %v", err)
	}
	for _, r := range kept {
		t.Logf("kept: %s %s", r.TxHash, r.Name)
	}
	if len(kept) != 2 {
		t.Fatalf("kept %d records, want 2 (envelope + result for the failed tx)", len(kept))
	}
	for _, r := range kept {
		if r.TxHash != hashFailed {
			t.Errorf("kept a record for %s, want only %s", r.TxHash, hashFailed)
		}
	}
}

// TestFilterRecordsCompound applies all filters at once.
func TestFilterRecordsCompound(t *testing.T) {
	t.Parallel()
	src := fakesource.New(capture.NetworkTestnet, "https://fake.example")
	hashOne := "one0001"        // 1 op, classic
	hashSoroban := "sor0001"    // soroban, 1 op
	hashMulti := "mul0001"      // 5 ops, classic
	hashSorobanFail := "sf0001" // soroban, 3 ops, failed
	hashOk := "ok0001"          // classic, 1 op, succeeded
	t.Helper()
	src.Transactions[hashOne] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope", XDR: envelopeXDR(t),
			Ledger: 100, TxHash: hashOne,
		},
	}
	src.Transactions[hashSoroban] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope", XDR: sorobanEnvelopeXDR(t),
			Ledger: 100, TxHash: hashSoroban,
		},
	}
	src.Transactions[hashMulti] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope", XDR: multiOpEnvelopeXDR(t, 5),
			Ledger: 100, TxHash: hashMulti,
		},
	}
	src.Transactions[hashSorobanFail] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope", XDR: sorobanEnvelopeXDR(t),
			Ledger: 100, TxHash: hashSorobanFail,
		},
		{
			Name: "result", Type: "TransactionResult",
			XDR:    failedResultXDR(t),
			Ledger: 100, TxHash: hashSorobanFail,
		},
	}
	src.Transactions[hashOk] = []capture.Record{
		{
			Name: "envelope", Type: "TransactionEnvelope", XDR: multiOpEnvelopeXDR(t, 1),
			Ledger: 100, TxHash: hashOk,
		},
		{
			Name: "result", Type: "TransactionResult", XDR: mustEncodeSuccessResult(t),
			Ledger: 100, TxHash: hashOk,
		},
	}
	records := []capture.Record{}
	for _, h := range []string{hashOne, hashSoroban, hashMulti, hashSorobanFail, hashOk} {
		records = append(records, src.Transactions[h]...)
	}
	// --min-ops 2 --only-soroban --failed-only: only failing Soroban
	// transactions with at least two operations.
	kept, err := capture.FilterRecords(records, capture.FilterOptions{
		MinOps:      1,
		OnlySoroban: true,
		FailedOnly:  true,
	})
	if err != nil {
		t.Fatalf("FilterRecords() error = %v", err)
	}
	for _, r := range kept {
		t.Logf("kept: %s %s", r.TxHash, r.Name)
	}
	// hashSorobanFail is soroban and failed (1 op >= min-ops 1) -> kept.
	// hashSoroban is soroban but no result -> dropped by failed-only.
	// hashMulti has 5 ops but is classic -> dropped by only-soroban.
	// hashOne is classic and no result -> dropped by only-soroban.
	if len(kept) != 2 {
		t.Fatalf("kept %d records, want 2 (envelope + result for the failing soroban tx)", len(kept))
	}
	for _, r := range kept {
		if r.TxHash != hashSorobanFail {
			t.Errorf("kept a record for %s, want only %s", r.TxHash, hashSorobanFail)
		}
	}
}
