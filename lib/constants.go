package libunlynx

import (
	"go.dedis.ch/onet/v3/log"
	"os"
	"sync"
	"time"

	"go.dedis.ch/onet/v3/simul/monitor"
)

func init() {
	timeout, err := time.ParseDuration(os.Getenv("CONN_TIMEOUT"))
	if err == nil {
		TIMEOUT = timeout
	} else {
		log.Warn("Couldn't parse CONN_TIMEOUT, using default value: ", TIMEOUT.String())
	}
}

// Global Variables
//______________________________________________________________________________________________________________________

// TIME is true if we use protocols with time measurements of computations.
var TIME = false

// VPARALLELIZE allows to choose the level of parallelization in the vector computations
const VPARALLELIZE = 100

// DIFFPRI enables the DRO protocol (Distributed Results Obfuscation)
const DIFFPRI = false

// TIMEOUT ddefines the default channel timeout
var TIMEOUT = 10 * time.Minute

// StartTimer starts measurement of time
func StartTimer(name string) *monitor.TimeMeasure {
	if TIME {
		return monitor.NewTimeMeasure(name)
	}
	return nil
}

// EndTimer finishes measurement of time
func EndTimer(timer *monitor.TimeMeasure) {
	if TIME {
		timer.Record()
	}
}

// StartParallelize starts parallelization by instanciating number of threads
func StartParallelize(nbrWg int) *sync.WaitGroup {
	var wg sync.WaitGroup
	wg.Add(nbrWg)
	return &wg
}

// EndParallelize waits for a number of threads to finish
func EndParallelize(wg *sync.WaitGroup) {
	wg.Wait()
}
