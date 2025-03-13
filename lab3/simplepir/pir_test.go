package simplepir

import (
	"math/big"
	"reflect"
	"testing"
)

func TestMatMul(t *testing.T) {
	// Helper to create bigint matrix from int64 slice
	createMat := func(rows, cols int, vals []int64) Mat {
		mat := InitMat(rows, cols)
		for i := 0; i < rows; i++ {
			for j := 0; j < cols; j++ {
				mat[i][j].SetInt64(vals[i*cols+j])
			}
		}
		return mat
	}

	mod := big.NewInt(7) // Use 7 as modulus for tests

	tests := []struct {
		name     string
		m1       Mat
		m2       Mat
		mod      *big.Int
		expected Mat
	}{
		{
			name:     "empty matrices",
			m1:       Mat{},
			m2:       Mat{},
			mod:      mod,
			expected: nil,
		},
		{
			name:     "incompatible dimensions",
			m1:       createMat(2, 3, []int64{1, 2, 3, 4, 5, 6}),
			m2:       createMat(2, 2, []int64{1, 2, 3, 4}),
			mod:      mod,
			expected: nil,
		},
		{
			name:     "1x1 matrices",
			m1:       createMat(1, 1, []int64{5}),
			m2:       createMat(1, 1, []int64{3}),
			mod:      mod,
			expected: createMat(1, 1, []int64{1}), // (5*3) mod 7 = 1
		},
		{
			name:     "2x2 matrices",
			m1:       createMat(2, 2, []int64{1, 2, 3, 4}),
			m2:       createMat(2, 2, []int64{5, 6, 7, 8}),
			mod:      mod,
			expected: createMat(2, 2, []int64{5, 1, 3, 6}), // Result mod 7
		},
		{
			name:     "large numbers",
			m1:       createMat(2, 2, []int64{100, 200, 300, 400}),
			m2:       createMat(2, 2, []int64{500, 600, 700, 800}),
			mod:      mod,
			expected: createMat(2, 2, []int64{2, 5, 1, 4}), // Result mod 7
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatMul(tt.m1, tt.m2, tt.mod)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("MatMul() = %v, want nil", result)
				}
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("MatMul() = %v, want %v", result, tt.expected)
			}
		})
	}
}
