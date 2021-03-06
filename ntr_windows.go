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
	procLsaFreeMemory       = advapi32.NewProc("LsaFreeMemory")
	procLsaOpenPolicy       = advapi32.NewProc("LsaOpenPolicy")
)

type Privilege string

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

	// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms721859(v=vs.85).aspx#lsa_policy_function_return_values
	// and https://msdn.microsoft.com/en-us/library/cc704588.aspx
	NTSTATUS_SUCCESS                = 0x00000000
	NTSTATUS_ACCESS_DENIED          = 0xC0000022
	NTSTATUS_INSUFFICIENT_RESOURCES = 0xC000009A
	NTSTATUS_INTERNAL_DB_ERROR      = 0xC0000158
	NTSTATUS_INVALID_HANDLE         = 0xC0000008
	NTSTATUS_INVALID_SERVER_STATE   = 0xC00000DC
	NTSTATUS_INVALID_PARAMETER      = 0xC000000D
	NTSTATUS_NO_SUCH_PRIVILEGE      = 0xC0000060
	NTSTATUS_OBJECT_NAME_NOT_FOUND  = 0xC0000034
	NTSTATUS_UNSUCCESSFUL           = 0xC0000001

	// See https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx
	SE_ASSIGNPRIMARYTOKEN_NAME     = Privilege("SeAssignPrimaryTokenPrivilege")
	SE_AUDIT_NAME                  = Privilege("SeAuditPrivilege")
	SE_BACKUP_NAME                 = Privilege("SeBackupPrivilege")
	SE_CHANGE_NOTIFY_NAME          = Privilege("SeChangeNotifyPrivilege")
	SE_CREATE_GLOBAL_NAME          = Privilege("SeCreateGlobalPrivilege")
	SE_CREATE_PAGEFILE_NAME        = Privilege("SeCreatePagefilePrivilege")
	SE_CREATE_PERMANENT_NAME       = Privilege("SeCreatePermanentPrivilege")
	SE_CREATE_SYMBOLIC_LINK_NAME   = Privilege("SeCreateSymbolicLinkPrivilege")
	SE_CREATE_TOKEN_NAME           = Privilege("SeCreateTokenPrivilege")
	SE_DEBUG_NAME                  = Privilege("SeDebugPrivilege")
	SE_ENABLE_DELEGATION_NAME      = Privilege("SeEnableDelegationPrivilege")
	SE_IMPERSONATE_NAME            = Privilege("SeImpersonatePrivilege")
	SE_INC_BASE_PRIORITY_NAME      = Privilege("SeIncreaseBasePriorityPrivilege")
	SE_INCREASE_QUOTA_NAME         = Privilege("SeIncreaseQuotaPrivilege")
	SE_INC_WORKING_SET_NAME        = Privilege("SeIncreaseWorkingSetPrivilege")
	SE_LOAD_DRIVER_NAME            = Privilege("SeLoadDriverPrivilege")
	SE_LOCK_MEMORY_NAME            = Privilege("SeLockMemoryPrivilege")
	SE_MACHINE_ACCOUNT_NAME        = Privilege("SeMachineAccountPrivilege")
	SE_MANAGE_VOLUME_NAME          = Privilege("SeManageVolumePrivilege")
	SE_PROF_SINGLE_PROCESS_NAME    = Privilege("SeProfileSingleProcessPrivilege")
	SE_RELABEL_NAME                = Privilege("SeRelabelPrivilege")
	SE_REMOTE_SHUTDOWN_NAME        = Privilege("SeRemoteShutdownPrivilege")
	SE_RESTORE_NAME                = Privilege("SeRestorePrivilege")
	SE_SECURITY_NAME               = Privilege("SeSecurityPrivilege")
	SE_SHUTDOWN_NAME               = Privilege("SeShutdownPrivilege")
	SE_SYNC_AGENT_NAME             = Privilege("SeSyncAgentPrivilege")
	SE_SYSTEM_ENVIRONMENT_NAME     = Privilege("SeSystemEnvironmentPrivilege")
	SE_SYSTEM_PROFILE_NAME         = Privilege("SeSystemProfilePrivilege")
	SE_SYSTEMTIME_NAME             = Privilege("SeSystemtimePrivilege")
	SE_TAKE_OWNERSHIP_NAME         = Privilege("SeTakeOwnershipPrivilege")
	SE_TCB_NAME                    = Privilege("SeTcbPrivilege")
	SE_TIME_ZONE_NAME              = Privilege("SeTimeZonePrivilege")
	SE_TRUSTED_CREDMAN_ACCESS_NAME = Privilege("SeTrustedCredManAccessPrivilege")
	SE_UNDOCK_NAME                 = Privilege("SeUndockPrivilege")
	SE_UNSOLICITED_INPUT_NAME      = Privilege("SeUnsolicitedInputPrivilege")
)

type AccessMask uint32

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
	if r1 != NTSTATUS_SUCCESS {
		err = fmt.Errorf("Received error %v when calling LsaOpenPolicy: %v", r1, e1)
	}
	return
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa378299(v=vs.85).aspx
func LsaOpenPolicy(
	systemName *LSAUnicodeString, // PLSA_UNICODE_STRING
	objectAttributes *LSAObjectAttributes, // PLSA_OBJECT_ATTRIBUTES
	desiredAccess AccessMask, // AccessMask
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
	if r1 != NTSTATUS_SUCCESS {
		err = fmt.Errorf("Received error %v when calling LsaOpenPolicy: %v", r1, e1)
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
	if r1 != NTSTATUS_SUCCESS {
		err = fmt.Errorf("Received error %v when calling LsaOpenPolicy: %v", r1, e1)
	}
	return
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721796(v=vs.85).aspx
func LsaFreeMemory(
	buffer uintptr, // PVOID
) (err error) {
	r1, _, e1 := syscall.Syscall(
		procLsaFreeMemory.Addr(),
		1,
		buffer,
		0,
		0,
	)
	if r1 != NTSTATUS_SUCCESS {
		err = fmt.Errorf("Received error %v when calling LsaFreeMemory: %v", r1, e1)
	}
	return
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721798(v=vs.85).aspx
func LsaLookupNames2() {
}

func LSAUnicodeStringMustCompile(s string) LSAUnicodeString {
	lsaUnicodeString, err := LSAUnicodeStringFromString(s)
	if err != nil {
		panic(err)
	}
	return lsaUnicodeString
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms722492(v=vs.85).aspx
func LSAUnicodeStringFromString(s string) (LSAUnicodeString, error) {
	utf16, err := syscall.UTF16FromString(s)
	if err != nil {
		return LSAUnicodeString{}, err
	}
	dwLen := len(utf16)
	if dwLen > 0x7ffe {
		return LSAUnicodeString{}, fmt.Errorf("LSA string:\n%v\n\nLSA string too long - it is %v characters, max allowed is 32766.", s, dwLen)
	}
	return LSAUnicodeString{
		Length:        uint16(2*dwLen - 2),
		MaximumLength: uint16(2 * dwLen),
		Buffer:        &utf16[0],
	}, nil
}

func AddPrivilegesToUser(username string, privileges ...Privilege) (err error) {
	pmSID, _, _, err := syscall.LookupSID("", username)
	if err != nil {
		return fmt.Errorf("Got error looking up SID: %v", err)
	}
	h := syscall.Handle(0)
	err = LsaOpenPolicy(nil, &LSAObjectAttributes{}, POLICY_ALL_ACCESS, &h)
	if err != nil {
		return fmt.Errorf("Got error opening policy: %v", err)
	}
	defer func() {
		err := LsaClose(h)
		if err != nil {
			fmt.Printf("Could not close handle, got error: %v", err)
		}
	}()
	a := []LSAUnicodeString{}
	for i := range privileges {
		r, err := LSAUnicodeStringFromString(string(privileges[i]))
		if err != nil {
			return fmt.Errorf("Got error interpreting string %v: %v", privileges[i], err)
		}
		a = append(a, r)
	}
	err = LsaAddAccountRights(h, pmSID, &a[0], uint32(len(a)))
	if err != nil {
		return fmt.Errorf("Got error adding account right: %v", err)
	}
	return nil
}
