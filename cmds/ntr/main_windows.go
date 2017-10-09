package main

import (
	"log"

	docopt "github.com/docopt/docopt-go"
	"github.com/taskcluster/ntr"
)

const (
	usage = `ntr
ntr is a command line utility similar to ntrights.exe that allows you to assign privileges
to a local user.

  Usage:
    ntr USER PRIVILEGE...
    ntr --help
    ntr --version

  Options:
    USER                     The username of the local user to assign privileges to.
    PRIVILEGE                Privilege(s) to be assigned to the local user.
                             Allowed values are:
                                     SeAssignPrimaryTokenPrivilege
                                     SeAuditPrivilege
                                     SeBackupPrivilege
                                     SeChangeNotifyPrivilege
                                     SeCreateGlobalPrivilege
                                     SeCreatePagefilePrivilege
                                     SeCreatePermanentPrivilege
                                     SeCreateSymbolicLinkPrivilege
                                     SeCreateTokenPrivilege
                                     SeDebugPrivilege
                                     SeEnableDelegationPrivilege
                                     SeImpersonatePrivilege
                                     SeIncreaseBasePriorityPrivilege
                                     SeIncreaseQuotaPrivilege
                                     SeIncreaseWorkingSetPrivilege
                                     SeLoadDriverPrivilege
                                     SeLockMemoryPrivilege
                                     SeMachineAccountPrivilege
                                     SeManageVolumePrivilege
                                     SeProfileSingleProcessPrivilege
                                     SeRelabelPrivilege
                                     SeRemoteShutdownPrivilege
                                     SeRestorePrivilege
                                     SeSecurityPrivilege
                                     SeShutdownPrivilege
                                     SeSyncAgentPrivilege
                                     SeSystemEnvironmentPrivilege
                                     SeSystemProfilePrivilege
                                     SeSystemtimePrivilege
                                     SeTakeOwnershipPrivilege
                                     SeTcbPrivilege
                                     SeTimeZonePrivilege
                                     SeTrustedCredManAccessPrivilege
                                     SeUndockPrivilege
                                     SeUnsolicitedInputPrivilege
    --help                   Display this help text.
    --version                The release version of ntr.

  Exit Codes:
    0      Privileges assigned to local user.
    1      Invalid parameters specified to command.
    64     Permissions not applied. Something went wrong.
`
	version = "1.0.0"
)

func main() {
	arguments, err := docopt.Parse(usage, nil, true, "ntr "+version, false, true)
	if err != nil {
		log.Println("Error parsing command line arguments!")
		log.Fatal(err)
	}
	user := arguments["USER"].(string)
	p := arguments["PRIVILEGE"].([]string)
	privileges := make([]ntr.Privilege, len(p), len(p))
	for i := range p {
		privileges[i] = (ntr.Privilege)(p[i])
	}

	err = ntr.AddPrivilegesToUser(user, privileges...)
	if err != nil {
		log.Fatalf("Hit error: %v", err)
	}
}
