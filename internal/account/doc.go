// Package account implements Certipy's `account` subcommand — creation,
// modification, deletion, and read-back of Active Directory user and
// computer accounts over LDAP.
//
// The package is a thin abuse-oriented wrapper around go-ldap Add / Modify /
// Del / Search. It exposes four entry points (Create, Update, Delete, Read)
// that all take an Options struct keyed off an already-bound *ldap.Conn. The
// Options.Target field accepts either a sAMAccountName (with or without the
// trailing "$" for computers) or a fully-qualified DN; resolution happens
// inside the package.
//
// Password writes are performed against the unicodePwd attribute in its
// UTF-16LE-quoted form; see UnicodePwd for the on-wire encoding.
package account
