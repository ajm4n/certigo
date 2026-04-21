package ldap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// Shell is a minimal interactive REPL that sits on top of a bound LDAP
// connection. It mirrors the most commonly used commands from Certipy's
// `--ldap-shell`: whoami, search, dn resolution, account create, RBCD
// set / clear, password change, account enable / disable.
//
// All writes go through the supplied io.Writer; all reads come from the
// supplied io.Reader. Callers typically pass os.Stdout + os.Stdin.
type Shell struct {
	Conn     *goldap.Conn
	BaseDN   string
	In       io.Reader
	Out      io.Writer
	Banner   string
	Prompt   string
	Username string // for whoami fallback
}

// Run drives the REPL until the user exits or input EOF is hit.
func (s *Shell) Run() error {
	if s.Conn == nil {
		return fmt.Errorf("ldap shell: nil connection")
	}
	if s.In == nil {
		s.In = os.Stdin
	}
	if s.Out == nil {
		s.Out = os.Stdout
	}
	if s.Prompt == "" {
		s.Prompt = "ldap# "
	}
	if s.Banner == "" {
		s.Banner = "certigo ldap shell - type 'help' for commands, 'exit' to quit"
	}
	fmt.Fprintln(s.Out, s.Banner)

	scanner := bufio.NewScanner(s.In)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for {
		fmt.Fprint(s.Out, s.Prompt)
		if !scanner.Scan() {
			fmt.Fprintln(s.Out)
			return nil
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		stop, err := s.dispatch(line)
		if err != nil {
			fmt.Fprintf(s.Out, "error: %v\n", err)
		}
		if stop {
			return nil
		}
	}
}

func (s *Shell) dispatch(line string) (stop bool, err error) {
	parts := splitArgs(line)
	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "?":
		s.help()
	case "exit", "quit":
		return true, nil
	case "whoami":
		return false, s.whoami()
	case "search":
		return false, s.cmdSearch(args)
	case "dn":
		return false, s.cmdDN(args)
	case "get":
		return false, s.cmdGet(args)
	case "add_computer":
		return false, s.cmdAddComputer(args)
	case "add_user":
		return false, s.cmdAddUser(args)
	case "add_user_to_group":
		return false, s.cmdAddUserToGroup(args)
	case "set_rbcd":
		return false, s.cmdSetRBCD(args)
	case "clear_rbcd":
		return false, s.cmdClearRBCD(args)
	case "change_password":
		return false, s.cmdChangePassword(args)
	case "disable_account":
		return false, s.uacFlag(args, true)
	case "enable_account":
		return false, s.uacFlag(args, false)
	default:
		fmt.Fprintf(s.Out, "unknown command %q - type 'help'\n", cmd)
	}
	return false, nil
}

func (s *Shell) help() {
	fmt.Fprintln(s.Out, "Commands:")
	fmt.Fprintln(s.Out, "  whoami")
	fmt.Fprintln(s.Out, "  search <ldap-filter> [attr1,attr2,...]")
	fmt.Fprintln(s.Out, "  dn <sAMAccountName>")
	fmt.Fprintln(s.Out, "  get <dn-or-sam>")
	fmt.Fprintln(s.Out, "  add_computer <name> <password>")
	fmt.Fprintln(s.Out, "  add_user <name> <password>")
	fmt.Fprintln(s.Out, "  add_user_to_group <user> <group>")
	fmt.Fprintln(s.Out, "  set_rbcd <source-sam> <target-sam>")
	fmt.Fprintln(s.Out, "  clear_rbcd <target-sam>")
	fmt.Fprintln(s.Out, "  change_password <user> <new-password>")
	fmt.Fprintln(s.Out, "  disable_account <user>")
	fmt.Fprintln(s.Out, "  enable_account <user>")
	fmt.Fprintln(s.Out, "  exit | quit")
}

func (s *Shell) whoami() error {
	r, err := s.Conn.WhoAmI(nil)
	if err != nil {
		if s.Username != "" {
			fmt.Fprintln(s.Out, s.Username)
			return nil
		}
		return err
	}
	fmt.Fprintln(s.Out, r.AuthzID)
	return nil
}

func (s *Shell) cmdSearch(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: search <filter> [attr1,attr2,...]")
	}
	filter := args[0]
	attrs := []string{"*"}
	if len(args) > 1 {
		attrs = strings.Split(args[1], ",")
	}
	req := goldap.NewSearchRequest(
		s.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		10, 0, false,
		filter,
		attrs,
		nil,
	)
	res, err := s.Conn.Search(req)
	if err != nil {
		return err
	}
	for _, e := range res.Entries {
		fmt.Fprintln(s.Out, e.DN)
		for _, a := range e.Attributes {
			for _, v := range a.Values {
				fmt.Fprintf(s.Out, "  %s: %s\n", a.Name, v)
			}
		}
		fmt.Fprintln(s.Out)
	}
	return nil
}

func (s *Shell) cmdDN(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: dn <sAMAccountName>")
	}
	dn, err := s.resolveDN(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintln(s.Out, dn)
	return nil
}

func (s *Shell) cmdGet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: get <dn-or-sam>")
	}
	dn := args[0]
	if !strings.Contains(dn, ",") {
		d, err := s.resolveDN(dn)
		if err != nil {
			return err
		}
		dn = d
	}
	req := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"*"},
		nil,
	)
	res, err := s.Conn.Search(req)
	if err != nil {
		return err
	}
	if len(res.Entries) == 0 {
		return fmt.Errorf("no entry at %s", dn)
	}
	e := res.Entries[0]
	fmt.Fprintln(s.Out, e.DN)
	for _, a := range e.Attributes {
		for _, v := range a.Values {
			fmt.Fprintf(s.Out, "  %s: %s\n", a.Name, v)
		}
	}
	return nil
}

func (s *Shell) cmdAddComputer(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: add_computer <name> <password>")
	}
	name, pwd := args[0], args[1]
	if !strings.HasSuffix(name, "$") {
		name += "$"
	}
	cn := strings.TrimSuffix(name, "$")
	dn := fmt.Sprintf("CN=%s,CN=Computers,%s", goldap.EscapeDN(cn), s.BaseDN)
	add := goldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	add.Attribute("cn", []string{cn})
	add.Attribute("sAMAccountName", []string{name})
	add.Attribute("userAccountControl", []string{"4098"}) // WORKSTATION_TRUST_ACCOUNT | ACCOUNTDISABLE
	if err := s.Conn.Add(add); err != nil {
		return err
	}
	mod := goldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{string(utf16Quoted(pwd))})
	mod.Replace("userAccountControl", []string{"4096"}) // enabled workstation
	if err := s.Conn.Modify(mod); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "created: %s\n", dn)
	return nil
}

func (s *Shell) cmdAddUser(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: add_user <name> <password>")
	}
	sam, pwd := args[0], args[1]
	dn := fmt.Sprintf("CN=%s,CN=Users,%s", goldap.EscapeDN(sam), s.BaseDN)
	add := goldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("cn", []string{sam})
	add.Attribute("sAMAccountName", []string{sam})
	add.Attribute("userAccountControl", []string{"514"}) // NORMAL_ACCOUNT | ACCOUNTDISABLE
	if err := s.Conn.Add(add); err != nil {
		return err
	}
	mod := goldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{string(utf16Quoted(pwd))})
	mod.Replace("userAccountControl", []string{"512"})
	if err := s.Conn.Modify(mod); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "created: %s\n", dn)
	return nil
}

func (s *Shell) cmdAddUserToGroup(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: add_user_to_group <user> <group>")
	}
	userDN, err := s.resolveDN(args[0])
	if err != nil {
		return err
	}
	groupDN, err := s.resolveDN(args[1])
	if err != nil {
		return err
	}
	mod := goldap.NewModifyRequest(groupDN, nil)
	mod.Add("member", []string{userDN})
	if err := s.Conn.Modify(mod); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "added %s to %s\n", userDN, groupDN)
	return nil
}

func (s *Shell) cmdSetRBCD(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: set_rbcd <source-sam> <target-sam>")
	}
	sourceSID, err := s.lookupSID(args[0])
	if err != nil {
		return fmt.Errorf("lookup source SID: %w", err)
	}
	targetDN, err := s.resolveDN(args[1])
	if err != nil {
		return err
	}
	sd, err := buildRBCDDescriptor(sourceSID)
	if err != nil {
		return err
	}
	mod := goldap.NewModifyRequest(targetDN, nil)
	mod.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sd)})
	if err := s.Conn.Modify(mod); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "RBCD set: %s -> %s (source SID %s)\n", args[0], targetDN, sourceSID)
	return nil
}

func (s *Shell) cmdClearRBCD(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: clear_rbcd <target-sam>")
	}
	targetDN, err := s.resolveDN(args[0])
	if err != nil {
		return err
	}
	mod := goldap.NewModifyRequest(targetDN, nil)
	mod.Delete("msDS-AllowedToActOnBehalfOfOtherIdentity", nil)
	if err := s.Conn.Modify(mod); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "cleared RBCD on %s\n", targetDN)
	return nil
}

func (s *Shell) cmdChangePassword(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: change_password <user> <new-password>")
	}
	dn, err := s.resolveDN(args[0])
	if err != nil {
		return err
	}
	mod := goldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{string(utf16Quoted(args[1]))})
	if err := s.Conn.Modify(mod); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "password changed for %s\n", dn)
	return nil
}

// uacFlag toggles the ACCOUNTDISABLE bit (0x0002) on userAccountControl.
// disable=true sets it, disable=false clears it.
func (s *Shell) uacFlag(args []string, disable bool) error {
	if len(args) != 1 {
		act := "disable_account"
		if !disable {
			act = "enable_account"
		}
		return fmt.Errorf("usage: %s <user>", act)
	}
	dn, err := s.resolveDN(args[0])
	if err != nil {
		return err
	}
	cur, err := s.fetchUAC(dn)
	if err != nil {
		return err
	}
	if disable {
		cur |= 0x0002
	} else {
		cur &^= 0x0002
	}
	mod := goldap.NewModifyRequest(dn, nil)
	mod.Replace("userAccountControl", []string{fmt.Sprintf("%d", cur)})
	if err := s.Conn.Modify(mod); err != nil {
		return err
	}
	word := "enabled"
	if disable {
		word = "disabled"
	}
	fmt.Fprintf(s.Out, "%s %s\n", word, dn)
	return nil
}

func (s *Shell) fetchUAC(dn string) (int, error) {
	req := goldap.NewSearchRequest(
		dn,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"userAccountControl"},
		nil,
	)
	res, err := s.Conn.Search(req)
	if err != nil {
		return 0, err
	}
	if len(res.Entries) == 0 {
		return 0, fmt.Errorf("no entry at %s", dn)
	}
	v := res.Entries[0].GetAttributeValue("userAccountControl")
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return 0, fmt.Errorf("parse UAC %q: %w", v, err)
	}
	return n, nil
}

// resolveDN returns the DN of sam. If sam already looks like a DN it is
// returned unchanged.
func (s *Shell) resolveDN(sam string) (string, error) {
	if strings.Contains(sam, "=") {
		return sam, nil
	}
	filter := fmt.Sprintf("(|(sAMAccountName=%s)(sAMAccountName=%s$))",
		goldap.EscapeFilter(sam),
		goldap.EscapeFilter(strings.TrimSuffix(sam, "$")),
	)
	req := goldap.NewSearchRequest(
		s.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		1, 0, false,
		filter,
		[]string{"distinguishedName"},
		nil,
	)
	res, err := s.Conn.Search(req)
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("no entry for sAMAccountName=%q", sam)
	}
	return res.Entries[0].DN, nil
}

// lookupSID resolves a sAMAccountName to its objectSid string.
func (s *Shell) lookupSID(sam string) (string, error) {
	filter := fmt.Sprintf("(|(sAMAccountName=%s)(sAMAccountName=%s$))",
		goldap.EscapeFilter(sam),
		goldap.EscapeFilter(strings.TrimSuffix(sam, "$")),
	)
	req := goldap.NewSearchRequest(
		s.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		1, 0, false,
		filter,
		[]string{"objectSid"},
		nil,
	)
	res, err := s.Conn.Search(req)
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("no entry for %q", sam)
	}
	raw := res.Entries[0].GetRawAttributeValue("objectSid")
	if len(raw) == 0 {
		return "", fmt.Errorf("entry has no objectSid")
	}
	return sidBytesToString(raw), nil
}

// utf16Quoted encodes a password as AD expects for unicodePwd writes:
// UTF-16-LE of "<pwd>" including the enclosing quotes.
func utf16Quoted(pwd string) []byte {
	quoted := `"` + pwd + `"`
	out := make([]byte, 2*len(quoted))
	for i, r := range quoted {
		out[i*2] = byte(r)
		out[i*2+1] = byte(uint16(r) >> 8)
	}
	return out
}

// sidBytesToString mirrors adcs.SIDFromBytes locally so the ldap package
// doesn't take a dep on adcs.
func sidBytesToString(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	rev := b[0]
	count := int(b[1])
	if len(b) < 8+4*count {
		return ""
	}
	var idAuth uint64
	for _, c := range b[2:8] {
		idAuth = idAuth<<8 | uint64(c)
	}
	parts := []string{"S", fmt.Sprintf("%d", rev), fmt.Sprintf("%d", idAuth)}
	for i := 0; i < count; i++ {
		off := 8 + 4*i
		sub := binary.LittleEndian.Uint32(b[off : off+4])
		parts = append(parts, fmt.Sprintf("%d", sub))
	}
	return strings.Join(parts, "-")
}

// buildRBCDDescriptor constructs a minimal self-relative
// nTSecurityDescriptor granting FULL_CONTROL to sourceSID. The layout
// follows MS-DTYP SECURITY_DESCRIPTOR + ACL + ACCESS_ALLOWED_ACE.
func buildRBCDDescriptor(sourceSID string) ([]byte, error) {
	sidBytes, err := sidStringToBytes(sourceSID)
	if err != nil {
		return nil, err
	}
	aceSize := 8 + len(sidBytes) // header(4) + mask(4) + sid
	aclSize := 8 + aceSize       // acl_revision(1)+sbz(1)+size(2)+count(2)+sbz(2) + aces

	sd := make([]byte, 0, 20+aclSize)
	sd = append(sd,
		0x01,       // Revision
		0x00,       // Sbz1
		0x04, 0x80, // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
	)
	// OffsetOwner=0, OffsetGroup=0, OffsetSacl=0, OffsetDacl=20
	sd = binary.LittleEndian.AppendUint32(sd, 0)
	sd = binary.LittleEndian.AppendUint32(sd, 0)
	sd = binary.LittleEndian.AppendUint32(sd, 0)
	sd = binary.LittleEndian.AppendUint32(sd, 20)

	// ACL header
	sd = append(sd, 0x02, 0x00) // AclRevision=2, Sbz1=0
	sd = binary.LittleEndian.AppendUint16(sd, uint16(aclSize))
	sd = binary.LittleEndian.AppendUint16(sd, 1) // AceCount=1
	sd = binary.LittleEndian.AppendUint16(sd, 0) // Sbz2

	// ACCESS_ALLOWED_ACE
	sd = append(sd, 0x00, 0x00) // AceType=ACCESS_ALLOWED, AceFlags=0
	sd = binary.LittleEndian.AppendUint16(sd, uint16(aceSize))
	sd = binary.LittleEndian.AppendUint32(sd, 0x000F01FF) // GENERIC_ALL / FULL_CONTROL
	sd = append(sd, sidBytes...)

	return sd, nil
}

// sidStringToBytes is the inverse of sidBytesToString - MS-DTYP §2.4.2.2
// binary encoding of a string SID.
func sidStringToBytes(sid string) ([]byte, error) {
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return nil, fmt.Errorf("invalid SID %q", sid)
	}
	var rev uint64
	fmt.Sscanf(parts[1], "%d", &rev)
	var idAuth uint64
	fmt.Sscanf(parts[2], "%d", &idAuth)
	subs := parts[3:]
	out := make([]byte, 0, 8+4*len(subs))
	out = append(out, byte(rev), byte(len(subs)))
	idAuthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(idAuthBytes, idAuth)
	out = append(out, idAuthBytes[2:]...)
	for _, s := range subs {
		var v uint32
		fmt.Sscanf(s, "%d", &v)
		out = binary.LittleEndian.AppendUint32(out, v)
	}
	return out, nil
}

// splitArgs tokenizes a command line respecting simple quoting.
// Matches Certipy's shell behavior closely enough for paste-friendly input.
func splitArgs(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
