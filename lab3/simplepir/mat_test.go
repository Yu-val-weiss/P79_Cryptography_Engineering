package simplepir

import (
	"math/big"
	"reflect"
	"testing"
)

func assertPanic(t *testing.T, f func(), msg string) {
	defer func() {
		if r := recover(); r == nil {
			t.Error(msg)
		}
	}()
	f()
}

func TestMatMul(t *testing.T) {
	mod := big.NewInt(7) // use 7 as modulus for tests
	tests := []struct {
		name     string
		m1       *Mat
		m2       *Mat
		mod      *big.Int
		expected *Mat
	}{
		{
			name:     "empty matrices",
			m1:       &Mat{},
			m2:       &Mat{},
			mod:      mod,
			expected: nil,
		},
		{
			name:     "incompatible dimensions",
			m1:       NewMat(2, 3).Fill([]int64{1, 2, 3, 4, 5, 6}),
			m2:       NewMat(2, 2).Fill([]int64{1, 2, 3, 4}),
			mod:      mod,
			expected: nil,
		},
		{
			name:     "1x1 matrices",
			m1:       NewMat(1, 1).Fill([]int64{5}),
			m2:       NewMat(1, 1).Fill([]int64{3}),
			mod:      mod,
			expected: NewMat(1, 1).Fill([]int64{1}), // 15 mod 7 = 1
		},
		{
			name:     "2x2 matrices",
			m1:       NewMat(2, 2).Fill([]int64{1, 2, 3, 4}),
			m2:       NewMat(2, 2).Fill([]int64{5, 6, 7, 8}),
			mod:      mod,
			expected: NewMat(2, 2).Fill([]int64{5, 1, 1, 1}), // Result mod 7
		},
		{
			name:     "large numbers",
			m1:       NewMat(2, 2).Fill([]int64{100, 200, 300, 400}),
			m2:       NewMat(2, 2).Fill([]int64{500, 600, 700, 800}),
			mod:      mod,
			expected: NewMat(2, 2).Fill([]int64{6, 4, 4, 4}), // Result mod 7
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mat_mul_f := func() *Mat { return tt.m1.MatMul(tt.m2, tt.mod) }
			if tt.expected == nil {
				assertPanic(t, func() { mat_mul_f() }, "expected panic about dimension mismatch")
				return
			}

			result := mat_mul_f()

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("MatMul() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVecMul(t *testing.T) {
	mod := big.NewInt(7) // use 7 as modulus for tests
	tests := []struct {
		name     string
		m        *Mat
		v        *Vec
		mod      *big.Int
		expected *Vec
	}{
		{
			name:     "empty matrices",
			m:        &Mat{},
			v:        &Vec{},
			mod:      mod,
			expected: nil,
		},
		{
			name:     "incompatible dimensions",
			m:        NewMat(2, 3).Fill([]int64{1, 2, 3, 4, 5, 6}),
			v:        NewVec(10).Fill([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
			mod:      mod,
			expected: nil,
		},
		{
			name:     "1x1 matrix and 1 vector",
			m:        NewMat(1, 1).Fill([]int64{5}),
			v:        NewVec(1).Fill([]int64{3}),
			mod:      mod,
			expected: NewVec(1).Fill([]int64{1}), // 15 mod 7 = 1
		},
		{
			name:     "2x2 matrices",
			m:        NewMat(2, 2).Fill([]int64{1, 2, 3, 4}),
			v:        NewVec(2).Fill([]int64{5, 6}),
			mod:      mod,
			expected: NewVec(2).Fill([]int64{3, 4}), // Result mod 7
		},
		{
			name:     "large numbers",
			m:        NewMat(2, 2).Fill([]int64{1_000_000, 2_000_000, 3_000_000, 4_000_000}),
			v:        NewVec(2).Fill([]int64{5_000_000, 6_000_000}),
			mod:      mod,
			expected: NewVec(2).Fill([]int64{3, 4}), // Result mod 7
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mat_mul_f := func() *Vec { return tt.m.VecMul(tt.v, tt.mod) }
			if tt.expected == nil {
				assertPanic(t, func() { mat_mul_f() }, "expected panic about dimension mismatch")
				return
			}

			result := mat_mul_f()

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("MatMul() = %v, want %v", result, tt.expected)
			}
		})
	}
}
