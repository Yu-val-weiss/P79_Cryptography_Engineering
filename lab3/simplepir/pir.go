package simplepir

import (
	"math/big"
)

// gauss sampler consts, sourced from Simple PIR
const (
	t     float64 = 0
	sigma float64 = 6.4
	tau   float64 = 18.4 // past this in un-tail trimmed version, the prob < 0.01
)

var chi GaussSampler = GaussSampler{t: t, sigma: sigma, tau: tau}

// Setup initializes the hint values
//
// Corresponds to Setup(db ∈ Z^{√𝑁×√𝑁}_p) -> (hintS,hintC)
//
// hintS seems unused, so it is omitted here
//
// In the slides hintC is called A'
//
// Source: Hezinger et al.'s Simple PIR (https://www.usenix.org/system/files/usenixsecurity23-henzinger.pdf)
func Setup(db, A *Mat, mod *big.Int) *Mat {
	return db.MatMul(A, mod) // hintC aka A'
}

type queryState struct {
	j int
	s *Vec
}

// Query generates the query vector
//
// takes indexes i,j and matrix A
//
// also depends on sqrtN and q, which are parameters of the scheme and a random sampler
func Query(i, j int, A *Mat, sqrtN int, q *big.Int, sampler Sampler) (queryState, *Vec) {
	v := NewVec(sqrtN).OneHot(i)
	s := NewVec(sqrtN).FillRandom(q)
	e_vals := make([]int64, sqrtN)
	for i := range sqrtN {
		e_vals[i] = int64(sampler.Sample())
	}
	e := NewVec(sqrtN).Fill(e_vals)
	q_over_2 := new(big.Int).Div(q, big.NewInt(2))
	return queryState{j, s}, A.VecMul(s, q).Add(e, q).Add(v.Scale(q_over_2, q), q)
}

// Answer computes the answer based on the query
//
// Inputs: takes the database db and the query qu
//
// Additional inputs: parameter q of the protocol
//
// responds with ans (called c' in the slides)
func Answer(db *Mat, qu *Vec, q *big.Int) *Vec {
	return db.VecMul(qu, q)
}

// Recover extracts the database value from the answer
//
// input: takes ans (c' in the slides)
//
// additional inputs: the state st (comprising j and s from [Query]), hintC aka A' and the modulus q.
//
// returns the bit value inside the database (i.e. true for 1 and false for 0)
func Recover(ans *Vec, st queryState, hintC *Mat, q *big.Int) bool {
	r := ans.Sub(hintC.VecMul(st.s, q), q)
	q_over_4 := new(big.Int).Div(q, big.NewInt(4))
	q_over_4_times_3 := new(big.Int).Mul(q_over_4, big.NewInt(3))

	ind := r.data[st.j]
	return ind.Cmp(q_over_4) >= 0 && ind.Cmp(q_over_4_times_3) <= 0
}
