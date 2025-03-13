package simplepir

import (
	"fmt"
	"math/big"
)

type Mat struct {
	mat        [][]*big.Int
	rows, cols int
}

func NewMat(rows, cols int) *Mat {
	if rows <= 0 || cols <= 0 {
		panic("cannot initialise matrix with non-positive dimension")
	}
	result := make([][]*big.Int, rows)
	for row := range rows {
		result[row] = make([]*big.Int, cols)
		for col := range cols {
			result[row][col] = big.NewInt(0)
		}
	}
	return &Mat{mat: result, rows: rows, cols: cols}
}

func (m *Mat) Dims() (int, int) { return m.rows, m.cols }

func (m1 *Mat) MatMul(m2 *Mat, mod *big.Int) *Mat {
	// check dimensions, if improper, panic
	if m1.rows == 0 || m1.cols == 0 || m2.cols == 0 || m1.cols != m2.rows {
		panic(fmt.Sprintf("incompatible dimensions (%v, %v) and (%v, %v)", m1.rows, m1.cols, m2.rows, m2.cols))
	}

	rows := m1.rows
	cols := m2.cols
	inner := m1.cols

	result := NewMat(rows, cols)

	temp := new(big.Int)
	for i := range rows {
		for j := range cols {
			sum := big.NewInt(0)
			for k := range inner {
				// multiply elements, store in temp
				temp.Mul(m1.mat[i][k], m2.mat[k][j])
				// take modulus, store in temp
				temp.Mod(temp, mod)
				// add temp to sum
				sum.Add(sum, temp)
				// take modulus of sum
				sum.Mod(sum, mod)
			}
			// put sum in array
			result.mat[i][j].Set(sum)
		}
	}
	return result
}

// Matrix multiplication of a vector, modulo mod
//
// Returns a new vector with the result
func (m *Mat) VecMul(v *Vec, mod *big.Int) *Vec {
	// check dimensions, if improper, panic
	if m.rows == 0 || m.cols == 0 || m.cols != v.size {
		panic(fmt.Sprintf("incompatible dimensions (%v, %v) and (%v)", m.rows, m.cols, v.size))
	}

	result := NewVec(v.size)

	temp := new(big.Int)
	for i := range m.rows {
		sum := big.NewInt(0)
		for j := range v.size {
			// multiply elements, store in temp
			temp.Mul(m.mat[i][j], v.vec[j])
			// take modulus, store in temp
			temp.Mod(temp, mod)
			// add temp to sum
			sum.Add(sum, temp)
			// take modulus of sum
			sum.Mod(sum, mod)

			// put sum in vector
			result.vec[i].Set(sum)
		}
	}
	return result

}

// Fills the matrix with the data in the int64 slice
//
// Returns a pointer to the filled matrix for convenience
func (m *Mat) Fill(data []int64) *Mat {
	if m.rows == 0 || m.cols == 0 {
		panic("nil matrix")
	}
	if m.rows*m.cols != len(data) {
		panic(fmt.Sprintf("size mismatch, got %vx%v and %v", m.rows, m.cols, len(data)))
	}
	for i := range m.rows {
		for j := range m.cols {
			m.mat[i][j].SetInt64(data[i*m.cols+j])
		}
	}
	return m
}
