package main

import (
	"log"

	"github.com/taskcluster/ntr"
)

func main() {
	err := ntr.AddPrivilegesToUser("GenericWorker", ntr.SE_ASSIGNPRIMARYTOKEN_NAME)
	if err != nil {
		log.Fatalf("Hit error: %v", err)
	}
}
