package lib

import (
	"sync"

	"gopkg.in/dedis/onet.v1/simul/monitor"
)

// Global Variables
//______________________________________________________________________________________________________________________

// TIME is true if we use protocols with time measurements of computations.
const TIME = false

// PARALLELIZE is true if we use protocols with parallelization of computations.
const PARALLELIZE = true

// VPARALLELIZE allows to choose the level of parallelization in the vector computations
const VPARALLELIZE = 100

// DIFFPRI enables the DRO protocol (Distributed Results Obfuscation)
const DIFFPRI = false

// StartTimer starts measurement of time
func StartTimer(name string) *monitor.TimeMeasure {
	var timer *monitor.TimeMeasure
	if TIME {
		timer = monitor.NewTimeMeasure(name)
	}
	return timer
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
	if PARALLELIZE {
		wg.Add(nbrWg)
	}
	return &wg
}

// EndParallelize waits for a number of threads to finish
func EndParallelize(wg *sync.WaitGroup) {
	if PARALLELIZE {
		wg.Wait()
	}
}
