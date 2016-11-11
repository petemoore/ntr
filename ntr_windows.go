package ntr

// Refer to https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
// for understanding the c++ -> go type mappings

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procLsaAddAccountRights = advapi32.NewProc("LsaAddAccountRights")
	procLsaClose            = advapi32.NewProc("LsaClose")
	procLsaOpenPolicy       = advapi32.NewProc("LsaOpenPolicy")
)

// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms721916(v=vs.85).aspx
// Values found in https://github.com/Victek/Tomato-RAF/blob/99ea203ea065ce7c79b481ee590938c01e2ff824/release/src/router/samba3/source/include/rpc_lsa.h#L247-L291
const (
	POLICY_VIEW_LOCAL_INFORMATION   = 0x00000001
	POLICY_VIEW_AUDIT_INFORMATION   = 0x00000002
	POLICY_GET_PRIVATE_INFORMATION  = 0x00000004
	POLICY_TRUST_ADMIN              = 0x00000008
	POLICY_CREATE_ACCOUNT           = 0x00000010
	POLICY_CREATE_SECRET            = 0x00000020
	POLICY_CREATE_PRIVILEGE         = 0x00000040
	POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080
	POLICY_SET_AUDIT_REQUIREMENTS   = 0x00000100
	POLICY_AUDIT_LOG_ADMIN          = 0x00000200
	POLICY_SERVER_ADMIN             = 0x00000400
	POLICY_LOOKUP_NAMES             = 0x00000800

	POLICY_READ = syscall.STANDARD_RIGHTS_READ |
		POLICY_VIEW_AUDIT_INFORMATION |
		POLICY_GET_PRIVATE_INFORMATION

	POLICY_WRITE = syscall.STANDARD_RIGHTS_WRITE |
		POLICY_TRUST_ADMIN |
		POLICY_CREATE_ACCOUNT |
		POLICY_CREATE_SECRET |
		POLICY_CREATE_PRIVILEGE |
		POLICY_SET_DEFAULT_QUOTA_LIMITS |
		POLICY_SET_AUDIT_REQUIREMENTS |
		POLICY_AUDIT_LOG_ADMIN |
		POLICY_SERVER_ADMIN

	POLICY_EXECUTE = syscall.STANDARD_RIGHTS_EXECUTE |
		POLICY_VIEW_LOCAL_INFORMATION |
		POLICY_LOOKUP_NAMES

	POLICY_ALL_ACCESS = syscall.STANDARD_RIGHTS_REQUIRED |
		POLICY_VIEW_LOCAL_INFORMATION |
		POLICY_VIEW_AUDIT_INFORMATION |
		POLICY_GET_PRIVATE_INFORMATION |
		POLICY_TRUST_ADMIN |
		POLICY_CREATE_ACCOUNT |
		POLICY_CREATE_SECRET |
		POLICY_CREATE_PRIVILEGE |
		POLICY_SET_DEFAULT_QUOTA_LIMITS |
		POLICY_SET_AUDIT_REQUIREMENTS |
		POLICY_AUDIT_LOG_ADMIN |
		POLICY_SERVER_ADMIN |
		POLICY_LOOKUP_NAMES
)

type ACCESS_MASK uint32

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721841(v=vs.85).aspx
type LSAUnicodeString struct {
	Length        uint16  // USHORT
	MaximumLength uint16  // USHORT
	Buffer        *uint16 // PWSTR
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721829(v=vs.85).aspx
type LSAObjectAttributes struct {
	Length                   uint32            // ULONG
	RootDirectory            syscall.Handle    // HANDLE
	ObjectName               *LSAUnicodeString // PLSA_UNICODE_STRING
	Attributes               uint32            // ULONG
	SecurityDescriptor       uintptr           // PVOID
	SecurityQualityOfService uintptr           // PVOID
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721787(v=vs.85).aspx
func LsaClose(
	objectHandle syscall.Handle, // LSA_HANDLE
) (err error) {
	r1, _, e1 := syscall.Syscall(
		procLsaClose.Addr(),
		1,
		uintptr(objectHandle),
		0,
		0,
	)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa378299(v=vs.85).aspx
func LsaOpenPolicy(
	systemName *LSAUnicodeString, // PLSA_UNICODE_STRING
	objectAttributes *LSAObjectAttributes, // PLSA_OBJECT_ATTRIBUTES
	desiredAccess ACCESS_MASK, // ACCESS_MASK
	policyHandle *syscall.Handle, // PLSA_HANDLE in/out
) (err error) {
	r1, _, e1 := syscall.Syscall6(
		procLsaOpenPolicy.Addr(),
		4,
		uintptr(unsafe.Pointer(systemName)),
		uintptr(unsafe.Pointer(objectAttributes)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(policyHandle)),
		0,
		0,
	)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721786(v=vs.85).aspx
func LsaAddAccountRights(
	policyHandle syscall.Handle, // LSA_HANDLE
	accountSid *syscall.SID, // PSID
	userRights *LSAUnicodeString, // PLSA_UNICODE_STRING
	countOfRights uint32, // ULONG
) (err error) {
	r1, _, e1 := syscall.Syscall6(
		procLsaAddAccountRights.Addr(),
		4,
		uintptr(policyHandle),
		uintptr(unsafe.Pointer(accountSid)),
		uintptr(unsafe.Pointer(userRights)),
		uintptr(countOfRights),
		0,
		0,
	)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms722492(v=vs.85).aspx
func LSAUnicodeStringPtrFromStringPtr(s *string) (*LSAUnicodeString, error) {
	if s == nil {
		return nil, nil
	}
	utf16, err := syscall.UTF16FromString(*s)
	if err != nil {
		return nil, err
	}
	dwLen := len(utf16)
	if dwLen > 0x7ffe {
		return nil, fmt.Errorf("LSA string:\n%v\n\nLSA string too long - it is %v characters, max allowed is 32766.", *s, dwLen)
	}
	return &LSAUnicodeString{
		Length:        uint16(2 * dwLen),
		MaximumLength: uint16(2*dwLen + 2),
		Buffer:        &utf16[0],
	}, nil
}
