package main

import (
	"log"

	"github.com/taskcluster/ntr"
)

func main() {
	err := ntr.AddPrivilegesToUser("GenericWorker", "SeAssignPrimaryTokenPrivilege")
	if err != nil {
		log.Fatalf("Hit error: %v", err)
	}
}
