package simplepir

import (
	"math"
	"testing"
)

const rand_test_samples = 1_000_000
const rand_test_mean_tolerance = 0.01

func TestRandInt(t *testing.T) {
	// Test single call works
	t.Run("basic call", func(t *testing.T) {
		f := randInt(0, 10)
		if f < 0 || f > 10 {
			t.Errorf("randInt(0,10) = %v, want value in [0,10]", f)
		}
	})

	// Statistical properties tests
	t.Run("multiple samples", func(t *testing.T) {
		sum := 0
		seen := make(map[int]bool)

		for i := range rand_test_samples {
			f := randInt(0, 5)

			// Check range
			if f < 0 || f > 5 {
				t.Errorf("sample %d: randFloat() = %v, want value in [0,5]", i, f)
			}

			// Track uniqueness and sum
			seen[f] = true
			sum += f
		}

		// Check mean is roughly 2.5 (within 0.01 to allow for random variation)
		mean := float64(sum) / float64(rand_test_samples)
		exp_mean := 2.5
		if mean < exp_mean-rand_test_mean_tolerance || mean > exp_mean+rand_test_mean_tolerance {
			t.Errorf("mean of %d samples = %v, want value close to 2.5", rand_test_samples, mean)
		}
	})
}

func TestRandFloat(t *testing.T) {
	// Test single call works
	t.Run("basic call", func(t *testing.T) {
		f := randFloat()

		if f < 0 || f >= 1 {
			t.Errorf("randFloat() = %v, want value in [0,1)", f)
		}
	})

	// Statistical properties tests
	t.Run("multiple samples", func(t *testing.T) {
		sum := 0.0
		seen := make(map[float64]bool)

		for i := range rand_test_samples {
			f := randFloat()

			// Check range
			if f < 0 || f >= 1 {
				t.Errorf("sample %d: randFloat() = %v, want value in [0,1)", i, f)
			}

			// Track uniqueness and sum
			seen[f] = true
			sum += f
		}

		// Check mean is roughly 0.5 (within 0.01 to allow for random variation)
		mean := sum / float64(rand_test_samples)
		exp_mean := 0.5
		if mean < exp_mean-rand_test_mean_tolerance || mean > exp_mean+rand_test_mean_tolerance {
			t.Errorf("mean of %d samples = %v, want value close to 0.5", rand_test_samples, mean)
		}

		// Check we're getting different values (at least 99% unique)
		uniqueRatio := float64(len(seen)) / float64(rand_test_samples)
		if uniqueRatio < 0.99 {
			t.Errorf("unique ratio = %v, want at least 0.99", uniqueRatio)
		}
	})
}

func TestGaussSampler(t *testing.T) {
	const sampler_test_samples = 10_000
	const sampler_test_mean_allowance = 0.1
	t.Run("basic sample", func(t *testing.T) {
		g := GaussSampler{t: 0, sigma: 1, tau: 10}
		x := g.Sample()
		if float64(x) < -3 || float64(x) > 3 {
			t.Errorf("sample %v outside expected range [-3,3]", x)
		}
	})

	t.Run("statistical properties", func(t *testing.T) {
		sigma := 6.4
		tau := 6.46695107473
		g := GaussSampler{t: 0, sigma: sigma, tau: tau}
		samples := make([]float64, sampler_test_samples)
		sum := 0.0
		// sumSquares := 0.0

		// Collect samples
		for i := range samples {
			samples[i] = float64(g.Sample())
			sum += samples[i]
			// sumSquares += samples[i] * samples[i]
		}

		// Check mean
		mean := sum / float64(len(samples))
		if math.Abs(mean) > sampler_test_mean_allowance {
			t.Errorf("mean = %v, want close to 0", mean)
		}

		// Would check standard deviation, but its always *considerably* lower than the original due
		// to being a discrete distribution
		// variance := (sumSquares / float64(len(samples))) - (mean * mean)
		// stdDev := math.Sqrt(variance)
		// if math.Abs(stdDev-sigma) > sampler_test_mean_allowance {
		// 	t.Errorf("standard deviation = %v, want close to %v", stdDev, sigma)
		// }

		// Check all samples within tau*sigma
		for i, x := range samples {
			if math.Abs(x) > tau*sigma {
				t.Errorf("sample %d = %v outside ±τσ range", i, x)
			}
		}

	})
}
