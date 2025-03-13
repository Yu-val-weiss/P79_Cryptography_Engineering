package main

import "github.com/yu-val-weiss/p79_cryptography_engineering/lab3/simplepir"

func main() {
	// simplepir.TestRandFloat()
	f := func(s simplepir.Sampler) {
		s.Sample()
	}
	f(&simplepir.GaussSampler{})
}
