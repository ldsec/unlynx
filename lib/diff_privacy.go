package lib

import (
	"github.com/r0fls/gostats"
	"math"
)

// GenerateNoiseValues generates a number of n noise values from a given probabilistic distribution
func GenerateNoiseValues(n int64, mean, b, quanta float64) []float64 {
	laplace := stats.Laplace(mean, b)

	noise := make([]float64, 0)

	start := 0
	for int64(len(noise)) < n {
		val := laplace.Pdf(float64(start))

		rep := math.Ceil(val / quanta)

		for i := 0; i < int(rep); i++ {

			if start == 0 {
				noise = append(noise, float64(start))
			} else {
				noise = append(noise, float64(start))
				noise = append(noise, float64(0-start))
			}

			if int64(len(noise)) >= n {
				break
			}
		}
		start++
	}

	return noise[:n]
}
