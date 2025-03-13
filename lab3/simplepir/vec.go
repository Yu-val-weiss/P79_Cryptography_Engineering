package simplepir

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Vec struct {
	vec  []*big.Int
	size int
}

func NewVec(n int) *Vec {
	if n <= 0 {
		panic("cannot initialise vector with non-positive size")
	}
	result := make([]*big.Int, n)
	for i := range result {
		result[i] = big.NewInt(0)
	}
	return &Vec{result, n}
}

func (v *Vec) Fill(values []int64) *Vec {
	if v.size != len(values) {
		panic(fmt.Sprintf("size mismatch, got vector of size %v and values of size %v", v.size, len(values)))
	}
	for i := range v.size {
		v.vec[i].SetInt64(values[i])
	}
	return v
}

// fills the vector with random values in the range [0,max)
//
// returns the newly filled vector
func (v *Vec) FillRandom(max *big.Int) *Vec {
	for i := range v.vec {
		r, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		v.vec[i].Set(r)
	}
	return v
}

// set v to the one-hot encoding vector of zeros, except 1 at index
//
// returns v
func (v *Vec) OneHot(index int) *Vec {
	for x := range v.vec {
		if x == index {
			v.vec[x].SetInt64(1)
		} else {
			v.vec[x].SetInt64(0)
		}
	}
	return v
}

// adds v1 and v2 (modulo mod) and return the new vector it creates
func (v1 *Vec) Add(v2 *Vec, mod *big.Int) *Vec {
	if v1.size == 0 || v2.size == 0 {
		panic("cannot add empty vectors")
	}
	if v1.size != v2.size {
		panic(fmt.Sprintf("sizes must match, got %v and %v", v1.size, v2.size))
	}
	result := NewVec(v1.size)

	temp := new(big.Int)
	for x := range v1.vec {
		temp.Add(v1.vec[x], v2.vec[x])
		result.vec[x].Mod(temp, mod)
	}
	return result
}

// computes v1 - v2 (modulo mod) and return the new vector it creates
func (v1 *Vec) Sub(v2 *Vec, mod *big.Int) *Vec {
	if v1.size == 0 || v2.size == 0 {
		panic("cannot subtract empty vectors")
	}
	if v1.size != v2.size {
		panic(fmt.Sprintf("sizes must match, got %v and %v", v1.size, v2.size))
	}
	result := NewVec(v1.size)

	temp := new(big.Int)
	for x := range v1.vec {
		temp.Sub(v1.vec[x], v2.vec[x])
		result.vec[x].Mod(temp, mod)
	}
	return result
}

func (v *Vec) Scale(value *big.Int, mod *big.Int) *Vec {
	result := NewVec(v.size)
	temp := new(big.Int)
	for i := range v.vec {
		temp.Mul(v.vec[i], value)
		result.vec[i].Mod(temp, mod)
	}
	return result
}
