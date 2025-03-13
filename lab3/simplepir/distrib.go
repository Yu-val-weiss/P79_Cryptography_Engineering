package simplepir

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

// return cryptographically secure random integer in range [min, max]
func randInt(min, max int) int {
	// crypo/[rand.Int] returns a value in the range [0,max)
	// so need to subtract min to get a valid max, and add 1 since we want the range to be inclusive
	if min >= max {
		panic(fmt.Errorf("min %v should be strictly < max %v", min, max))
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max+1-min)))
	if err != nil {
		panic(err)
	}
	n := nBig.Int64()
	return int(n) + min
}

// Generate a secure random float in the range [0,1) using [rand.Int]
func randFloat() float64 {
	// create a random int made up of 53 bits, as the mantissa of float64 is 53 bits.
	max := big.NewInt(1<<53 - 1)
	f, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	// Float64 returns the float64 value nearest x
	randFloat, _ := f.Float64()

	return randFloat / (1 << 53)
}

type Sampler interface {
	Sample() int
}

type GaussSampler struct {
	t     float64 // Center t: the mean of the Gaussian
	sigma float64 // Stdev σ: the standard deviation of the Gaussian
	tau   float64 // Tailcut τ: a sample σ is at most τσ from the center with overwhelming probability.
}

// Sample from discrete Gaussian distribution
//
// Implicit input (from struct): A center t : float, and a parameter σ : float, and a tailcut parameter τ : float
//
//   - Center t: the mean of the Gaussian
//   - Stdev σ: the standard deviation of the Gaussian
//   - Tailcut τ: a sample σ is at most τσ from the center with overwhelming probability.
//
// source: https://link.springer.com/chapter/10.1007/978-3-642-34961-4_26
func (g GaussSampler) Sample() int {
	h := -math.Pi / (g.sigma * g.sigma)
	xMax := math.Ceil(g.t + g.tau*g.sigma)
	xMin := math.Floor(g.t - g.tau*g.sigma)

	for {
		x := randInt(int(xMin), int(xMax))
		p := math.Exp(h * math.Pow(float64(x)-g.t, 2))
		r := randFloat()
		if r < p {
			return x
		}
	}
}
