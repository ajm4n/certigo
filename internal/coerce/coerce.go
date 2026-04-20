// Package coerce provides DCOM/RPC triggers that force a target server
// to authenticate to an attacker-controlled URL — a standard pattern for
// catching NTLM tickets for relay.
//
// All three implementations are currently stubs returning ErrUnimplemented,
// pending MS-EFSR / MS-DFSNM / MS-RPRN bindings through go-msrpc or
// hand-rolled ncacn_np clients.
package coerce

import (
	"errors"
)

// ErrUnimplemented is returned by every trigger until we produce working
// RPC clients.
var ErrUnimplemented = errors.New("coerce: RPC trigger not yet implemented")

// TriggerPetitPotam invokes MS-EFSR EfsRpcOpenFileRaw against target to coax
// it into authenticating to attackerURL (a UNC / HTTP path).
func TriggerPetitPotam(target, attackerURL, username, password string) error {
	return ErrUnimplemented
}

// TriggerDFSCoerce invokes MS-DFSNM NetrDfsRemoveStdRoot with an
// attacker-controlled path.
func TriggerDFSCoerce(target, attackerURL, username, password string) error {
	return ErrUnimplemented
}

// TriggerPrinterBug invokes MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx
// (SpoolSample) to coerce the Print Spooler.
func TriggerPrinterBug(target, attackerURL, username, password string) error {
	return ErrUnimplemented
}
