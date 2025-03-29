package simplepir

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func TestSetup(t *testing.T) {
	testCases := []struct {
		name    string
		dbRows  int
		dbCols  int
		modulus int64
	}{
		{"Small database", 4, 4, 23},
		{"Medium database", 16, 16, 97},
		{"Large database", 32, 32, 257},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mod := big.NewInt(tc.modulus)
			db := NewMat(tc.dbRows, tc.dbCols).FillRandom(mod)
			A := NewMat(tc.dbCols, tc.dbCols).FillRandom(mod)

			hintC := Setup(db, A, mod)

			// Verify hintC = db * A
			expected := db.MatMul(A, mod)
			if !reflect.DeepEqual(expected, hintC) {
				t.Fatalf("Setup failed: hintC is incorrect.\nExpected: %v\nGot: %v", expected, hintC)
			}

			// Check dimensions
			if hintC.rows != db.rows || hintC.cols != A.cols {
				t.Fatalf("Setup failed: hintC has wrong dimensions. Expected: (%d,%d), Got: (%d,%d)",
					db.rows, A.cols, hintC.rows, hintC.cols)
			}
		})
	}
}

func TestQuery(t *testing.T) {
	testCases := []struct {
		name    string
		sqrtN   int
		modulus int64
		i       int
		j       int
	}{
		{"Small database", 4, 23, 1, 2},
		{"Medium database", 16, 97, 5, 10},
		{"Large database", 32, 257, 15, 20},
		{"Edge case - first element", 8, 101, 0, 0},
		{"Edge case - last element", 8, 101, 7, 7},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			q := big.NewInt(tc.modulus)
			A := NewMat(tc.sqrtN, tc.sqrtN).FillRandom(q)
			sampler := chi

			// Verify i and j are in bounds
			if tc.i < 0 || tc.i >= tc.sqrtN || tc.j < 0 || tc.j >= tc.sqrtN {
				t.Fatalf("Invalid index values: i=%d, j=%d for sqrtN=%d", tc.i, tc.j, tc.sqrtN)
			}

			st, qu := Query(tc.i, tc.j, A, tc.sqrtN, q, sampler)

			// Basic checks
			if qu == nil {
				t.Fatal("Query failed: qu is nil")
			}

			if st.j != tc.j {
				t.Errorf("Query state incorrect: expected j=%d, got j=%d", tc.j, st.j)
			}

			if st.s == nil {
				t.Fatal("Query state incorrect: s is nil")
			}

			// Check query vector dimensions
			if qu.size != tc.sqrtN {
				t.Errorf("Query vector has wrong size: expected %d, got %d", tc.sqrtN, qu.size)
			}

			// Verify values are in range [0, q-1]
			for i := range qu.size {
				if qu.data[i].Cmp(big.NewInt(0)) < 0 || qu.data[i].Cmp(q) >= 0 {
					t.Errorf("Query vector contains out-of-range value at index %d: %v", i, qu.data[i])
				}
			}
		})
	}
}

func TestAnswer(t *testing.T) {
	testCases := []struct {
		name    string
		dbRows  int
		dbCols  int
		modulus int64
	}{
		{"Small database", 4, 4, 23},
		{"Medium database", 16, 16, 97},
		{"Large database", 32, 32, 257},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mod := big.NewInt(tc.modulus)
			db := NewMat(tc.dbRows, tc.dbCols).FillRandom(mod)
			qu := NewVec(tc.dbCols).FillRandom(mod)

			ans := Answer(db, qu, mod)

			// Basic check
			if ans == nil {
				t.Fatal("Answer failed: ans is nil")
			}

			// Check answer vector dimensions
			if ans.size != tc.dbRows {
				t.Errorf("Answer vector has wrong size: expected %d, got %d", tc.dbRows, ans.size)
			}

			// Verify answer = db * qu
			expected := db.VecMul(qu, mod)
			if !reflect.DeepEqual(expected, ans) {
				t.Fatalf("Answer calculation incorrect.\nExpected: %v\nGot: %v", expected, ans)
			}

			// Verify values are in range [0, mod-1]
			for i := range ans.size {
				if ans.data[i].Cmp(big.NewInt(0)) < 0 || ans.data[i].Cmp(mod) >= 0 {
					t.Errorf("Answer vector contains out-of-range value at index %d: %v", i, ans.data[i])
				}
			}
		})
	}
}

func TestFullProtocol(t *testing.T) {
	testCases := []struct {
		name    string
		sqrtN   int
		modulus int64
		bits    int
	}{
		{"Small database", 4, 1 << 10, 1},
		{"Medium database", 16, 1 << 16, 1},
		{"Large database", 32, 1 << 20, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mod := big.NewInt(tc.modulus)

			// Create database with known values
			db := NewMat(tc.sqrtN, tc.sqrtN)
			for i := range tc.sqrtN {
				for j := range tc.sqrtN {
					// Fill with 0s and 1s in a checkerboard pattern
					if (i+j)%2 == 0 {
						db.data[i][j] = big.NewInt(0)
					} else {
						db.data[i][j] = big.NewInt(1)
					}
				}
			}

			// Initialize scheme
			A := NewMat(tc.sqrtN, tc.sqrtN).FillRandom(mod)
			hintC := Setup(db, A, mod)

			// Test multiple positions
			for i := range tc.sqrtN {
				for j := range tc.sqrtN {
					t.Run(fmt.Sprintf("Position_%d_%d", i, j), func(t *testing.T) {
						// Create query
						st, qu := Query(i, j, A, tc.sqrtN, mod, chi)

						// Generate answer
						ans := Answer(db, qu, mod)

						// Recover the result
						result := Recover(ans, st, hintC, mod)

						// Verify result
						expected := byte(db.data[i][j].Bit(0))
						if result != expected {
							t.Errorf("Recover failed at position (%d,%d): got %v, expected %v", i, j, result, expected)
						}
					})
				}
			}
		})
	}
}

func TestRecover(t *testing.T) {
	// The issue might be with the modulus value or the way we test recovery
	// Let's use a known working modulus and simplify the test

	// Use a proper power-of-2 modulus as recommended for SimplePIR
	mod := big.NewInt(1 << 14) // 16384, large enough for the PIR scheme

	sqrtN := 8 // Reduced size for easier debugging
	sampler := chi

	t.Run("SimpleRecoveryTest", func(t *testing.T) {
		// Create a deterministic database with known values for testing
		db := NewMat(sqrtN, sqrtN)
		for i := range sqrtN {
			for j := range sqrtN {
				// Simple pattern: even indices get 0, odd indices get 1
				if (i+j)%2 == 0 {
					db.data[i][j] = big.NewInt(0)
				} else {
					db.data[i][j] = big.NewInt(1)
				}
			}
		}

		// Initialize a deterministic matrix A instead of random
		A := NewMat(sqrtN, sqrtN)
		for i := range sqrtN {
			for j := range sqrtN {
				// Simple initialization to ensure A is invertible
				if i == j {
					A.data[i][j] = big.NewInt(1) // Identity matrix
				} else {
					A.data[i][j] = big.NewInt(0)
				}
			}
		}

		// Pre-compute the hint once
		hintC := Setup(db, A, mod)

		// Test a single element first to debug
		i, j := 1, 2 // Choose coordinates where we know the value
		expected := byte(db.data[i][j].Bit(0))

		// Go through the full protocol with detailed logging
		st, qu := Query(i, j, A, sqrtN, mod, sampler)

		// Verify the state has correct j value
		if st.j != j {
			t.Errorf("Query state has incorrect j value: expected %d, got %d", j, st.j)
		}

		ans := Answer(db, qu, mod)

		// Print intermediate values for debugging
		t.Logf("Testing recovery for position (%d,%d), expected value: %d", i, j, expected)
		t.Logf("hintC dimensions: %dx%d", hintC.rows, hintC.cols)
		t.Logf("answer vector size: %d", ans.size)

		result := Recover(ans, st, hintC, mod)

		if result != expected {
			t.Errorf("Recovery failed at (%d,%d): got %v, expected %v", i, j, result, expected)
		} else {
			t.Logf("Recovery succeeded for position (%d,%d)", i, j)
		}
	})

	// If the simple test passes, try with more iterations
	t.Run("MultipleRecoveryTests", func(t *testing.T) {
		if t.Failed() {
			t.Skip("Skipping multiple tests since the simple test failed")
		}

		// Create a binary database with random values
		db := NewMat(sqrtN, sqrtN).FillRandom(big.NewInt(2))

		// Use a deterministic A matrix for testing
		A := NewMat(sqrtN, sqrtN)
		for i := range sqrtN {
			for j := range sqrtN {
				A.data[i][j] = big.NewInt(int64(i+j+1) % mod.Int64())
			}
		}

		hintC := Setup(db, A, mod)

		// Test a few random positions
		testPositions := []struct{ i, j int }{
			{0, 0},
			{sqrtN - 1, sqrtN - 1},
			{sqrtN / 2, sqrtN / 2},
			{1, 3},
			{3, 1},
		}

		for _, pos := range testPositions {
			i, j := pos.i, pos.j
			expected := byte(db.data[i][j].Bit(0))

			st, qu := Query(i, j, A, sqrtN, mod, sampler)
			ans := Answer(db, qu, mod)
			result := Recover(ans, st, hintC, mod)

			if result != expected {
				t.Errorf("Recovery failed at (%d,%d): got %v, expected %v", i, j, result, expected)
			}
		}
	})
}

func TestEdgeCases(t *testing.T) {
	// Test with different moduli values
	moduli := []int64{1 << 10, 1 << 14, 1 << 20}
	sqrtN := 8

	// Test with all-zeros database
	t.Run("AllZeros", func(t *testing.T) {
		for _, modVal := range moduli {
			mod := big.NewInt(modVal)
			db := NewMat(sqrtN, sqrtN)
			// Fill with zeros
			for i := range sqrtN {
				for j := range sqrtN {
					db.data[i][j] = big.NewInt(0)
				}
			}

			A := NewMat(sqrtN, sqrtN).FillRandom(mod)
			hintC := Setup(db, A, mod)

			// Test a few positions
			for _, idx := range []int{0, sqrtN / 2, sqrtN - 1} {
				st, qu := Query(idx, idx, A, sqrtN, mod, chi)
				ans := Answer(db, qu, mod)
				result := Recover(ans, st, hintC, mod)

				expected := byte(0)
				if result != expected {
					t.Errorf("Failed with all-zero DB at pos (%d,%d): got %v, expected %v", idx, idx, result, expected)
				}
			}
		}
	})

	// Test with all-ones database
	t.Run("AllOnes", func(t *testing.T) {
		for _, modVal := range moduli {
			mod := big.NewInt(modVal)
			db := NewMat(sqrtN, sqrtN)
			// Fill with ones
			for i := range sqrtN {
				for j := range sqrtN {
					db.data[i][j] = big.NewInt(1)
				}
			}

			A := NewMat(sqrtN, sqrtN).FillRandom(mod)
			hintC := Setup(db, A, mod)

			// Test a few positions
			for _, idx := range []int{0, sqrtN / 2, sqrtN - 1} {
				st, qu := Query(idx, idx, A, sqrtN, mod, chi)
				ans := Answer(db, qu, mod)
				result := Recover(ans, st, hintC, mod)

				expected := byte(1)
				if result != expected {
					t.Errorf("Failed with all-one DB at pos (%d,%d): got %v, expected %v", idx, idx, result, expected)
				}
			}
		}
	})
}
