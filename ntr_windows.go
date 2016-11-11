package ntr

import (
	"syscall"
	"unsafe"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procLsaOpenPolicy = advapi32.NewProc("LsaOpenPolicy")
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

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa378299(v=vs.85).aspx
func LsaOpenPolicy(
	systemName *LSAUnicodeString, // PLSA_UNICODE_STRING
	objectAttributes *LSAObjectAttributes, // PLSA_OBJECT_ATTRIBUTES
	desiredAccess ACCESS_MASK, // ACCESS_MASK
	policyHandle syscall.Handle, // PLSA_HANDLE
) (err error) {
	r1, _, e1 := syscall.Syscall6(
		procLsaOpenPolicy.Addr(),
		4,
		uintptr(unsafe.Pointer(systemName)),
		uintptr(unsafe.Pointer(objectAttributes)),
		uintptr(desiredAccess),
		uintptr(policyHandle),
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
