package prio_utils

type CheckerPool struct {
	serverIdx int
	leaderIdx int
	buffer    chan *Checker
}

func (pool *CheckerPool) get() interface{} {
	select {
	case out := <-pool.buffer:
		return out
		//	default:
		//		return mpc.NewChecker(p.cfg, p.serverIdx, p.leaderIdx)
	}
}

