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
	h := syscall.Handle(0)
	err = ntr.LsaOpenPolicy(nil, &ntr.LSAObjectAttributes{}, ntr.POLICY_ALL_ACCESS, &h)
	if err != nil {
		log.Fatalf("Got error opening policy: %v", err)
	}
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
	a := []ntr.LSAUnicodeString{r}
	err = ntr.LsaAddAccountRights(h, pmSID, &a[0], 1)
	if err != nil {
		log.Fatalf("Got error adding account right: %v", err)
	}
}
