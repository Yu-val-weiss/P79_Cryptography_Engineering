package simplepir

import (
	"math/big"
	"math/rand"
)

// Parameters for SimplePIR
var (
	N    int
	n, q int64
	p    int64 = 2 // Plaintext modulus
)

type Mat = [][]*big.Int

func InitMat(rows, cols int) Mat {
	result := make(Mat, rows)
	for row := range rows {
		result[row] = make([]*big.Int, cols)
		for col := range cols {
			result[row][col] = big.NewInt(0)
		}
	}
	return result
}

func MatMul(m1, m2 Mat, mod *big.Int) Mat {
	// check dimensions, if improper, return nil
	if len(m1) == 0 || len(m2) == 0 || len(m1[0]) != len(m2) {
		return nil
	}

	rows := len(m1)
	cols := len(m2[0])
	inner := len(m1[0])

	result := InitMat(rows, cols)

	temp := new(big.Int)
	for i := range rows {
		for j := range cols {
			sum := big.NewInt(0)
			for k := range inner {
				// multiply elements, store in temp
				temp.Mul(m1[i][k], m2[k][j])
				// take modulus, store in temp
				temp.Mod(temp, mod)
				// add temp to sum
				sum.Add(sum, temp)
				// take modulus of sum
				sum.Mod(sum, mod)
			}
			// put sum in array
			result[i][j].Set(sum)
		}
	}
	return result
}

// Setup initializes the hint values
//
// Corresponds to Setup(db ∈ Z^{√𝑁×√𝑁}_p) -> (hint_s,hint_c)
//
// However hint_s seems unused, so it is omitted here
//
// Source: Hezinger et al.'s Simple PIR (https://www.usenix.org/system/files/usenixsecurity23-henzinger.pdf)
func Setup(db, A Mat, mod *big.Int) Mat {
	return MatMul(db, A, mod) // hint_c
}

// Query generates the query vector
func Query(i, j int, sqrtN int, A [][]bool) ([]int, []bool) {
	s := make([]bool, sqrtN)
	for i := range s {
		s[i] = rand.Intn(2) == 1
	}

	uicol := make([]bool, sqrtN)
	uicol[j] = true

	qu := make([]bool, sqrtN)
	for i := range qu {
		qu[i] = false
		for j := range A[i] {
			qu[i] = qu[i] != (A[i][j] && s[j])
		}
		qu[i] = qu[i] != uicol[i]
	}

	return []int{i, j}, qu
}

// Answer computes the answer based on the query
func Answer(db [][]bool, qu []bool) []bool {
	ans := make([]bool, len(db))
	for i := range db {
		ans[i] = false
		for j := range db[i] {
			ans[i] = ans[i] != (db[i][j] && qu[j])
		}
	}
	return ans
}

// Recover extracts the database value
func Recover(st []int, hintc [][]bool, ans []bool) bool {
	irow := st[0]
	s := make([]bool, len(hintc[irow]))
	for i := range s {
		s[i] = rand.Intn(2) == 1
	}

	dHat := ans[irow]
	for j := range hintc[irow] {
		dHat = dHat != (hintc[irow][j] && s[j])
	}

	return dHat
}
