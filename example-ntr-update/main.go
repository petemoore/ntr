package main

import (
	"log"
	"syscall"

	"github.com/taskcluster/ntr"
)

func main() {
	pmSID, _, _, err := syscall.LookupSID("", "GenericWorker")
	if err != nil {
		log.Fatalf("Got error looking up SID: %v", err)
	}
	sidString, err := pmSID.String()
	if err != nil {
		log.Fatalf("Got error converting SID to string: %v", err)
	}
	log.Printf("SID: %v", sidString)
	h := syscall.Handle(0)
	systemName := "WIN-7LN26LS103P"
	l, err := ntr.LSAUnicodeStringFromString(systemName)
	if err != nil {
		log.Fatalf("Got error interpreting string %v: %v", systemName, err)
	}
	err = ntr.LsaOpenPolicy(&l, &ntr.LSAObjectAttributes{}, ntr.POLICY_ALL_ACCESS, &h)
	if err != nil {
		log.Fatalf("Got error opening policy: %v", err)
	}
	log.Printf("Handle: %v", h)
	defer func() {
		err := ntr.LsaClose(h)
		if err != nil {
			log.Fatalf("Could not close handle, got error: %v", err)
		}
	}()
	rights := "SeAssignPrimaryTokenPrivilege"
	r, err := ntr.LSAUnicodeStringFromString(rights)
	if err != nil {
		log.Fatalf("Got error interpreting string %v: %v", rights, err)
	}
	a := [1]ntr.LSAUnicodeString{r}
	err = ntr.LsaAddAccountRights(h, pmSID, &a[0], 1)
	if err != nil {
		log.Fatalf("Got error adding account right: %v", err)
	}
}
