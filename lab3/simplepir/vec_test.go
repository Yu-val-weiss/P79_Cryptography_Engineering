package simplepir

import (
	"math/big"
	"testing"
)

func TestNewVec(t *testing.T) {
	t.Run("valid size", func(t *testing.T) {
		v := NewVec(5)
		if v.size != 5 {
			t.Errorf("NewVec(5).Size() = %v, want 5", v.size)
		}
		for i, val := range v.vec {
			if val.Int64() != 0 {
				t.Errorf("NewVec(5).vec[%v] = %v, want 0", i, val)
			}
		}
	})

	t.Run("invalid size", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("NewVec(0) did not panic")
			}
		}()
		NewVec(0)
	})
}

func TestFill(t *testing.T) {
	t.Run("valid fill", func(t *testing.T) {
		v := NewVec(3)
		values := []int64{1, 2, 3}
		v.Fill(values)
		for i, val := range v.vec {
			if val.Int64() != values[i] {
				t.Errorf("Fill() index %v = %v, want %v", i, val, values[i])
			}
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Fill() with size mismatch did not panic")
			}
		}()
		v := NewVec(3)
		v.Fill([]int64{1, 2})
	})
}

func TestFillRandom(t *testing.T) {
	max := big.NewInt(100)
	v := NewVec(1000)
	v.FillRandom(max)

	for i, val := range v.vec {
		if val.Cmp(max) >= 0 || val.Sign() < 0 {
			t.Errorf("FillRandom() index %v = %v, want value in [0,%v)", i, val, max)
		}
	}
}

func TestOneHot(t *testing.T) {
	size := 5
	for idx := 0; idx < size; idx++ {
		v := NewVec(size)
		v.OneHot(idx)

		for i, val := range v.vec {
			expected := int64(0)
			if i == idx {
				expected = 1
			}
			if val.Int64() != expected {
				t.Errorf("OneHot(%v) index %v = %v, want %v", idx, i, val, expected)
			}
		}
	}
}

func TestAdd(t *testing.T) {
	t.Run("basic addition", func(t *testing.T) {
		v1 := NewVec(3).Fill([]int64{1, 2, 3})
		v2 := NewVec(3).Fill([]int64{4, 5, 6})
		mod := big.NewInt(100)

		result := v1.Add(v2, mod)
		expected := []int64{5, 7, 9}

		for i, val := range result.vec {
			if val.Int64() != expected[i] {
				t.Errorf("Add() index %v = %v, want %v", i, val, expected[i])
			}
		}
	})

	t.Run("modular addition", func(t *testing.T) {
		v1 := NewVec(2).Fill([]int64{7, 8})
		v2 := NewVec(2).Fill([]int64{5, 6})
		mod := big.NewInt(10)

		result := v1.Add(v2, mod)
		expected := []int64{2, 4} // (7+5)%10=2, (8+6)%10=4

		for i, val := range result.vec {
			if val.Int64() != expected[i] {
				t.Errorf("Add() with mod index %v = %v, want %v", i, val, expected[i])
			}
		}
	})
}

func TestSub(t *testing.T) {
	t.Run("basic subtraction", func(t *testing.T) {
		v1 := NewVec(3).Fill([]int64{4, 5, 6})
		v2 := NewVec(3).Fill([]int64{1, 2, 3})
		mod := big.NewInt(100)

		result := v1.Sub(v2, mod)
		expected := []int64{3, 3, 3}

		for i, val := range result.vec {
			if val.Int64() != expected[i] {
				t.Errorf("Sub() index %v = %v, want %v", i, val, expected[i])
			}
		}
	})

	t.Run("modular subtraction", func(t *testing.T) {
		v1 := NewVec(2).Fill([]int64{2, 3})
		v2 := NewVec(2).Fill([]int64{5, 7})
		mod := big.NewInt(10)

		result := v1.Sub(v2, mod)
		expected := []int64{7, 6} // (2-5)%10=7, (3-7)%10=6

		for i, val := range result.vec {
			if val.Int64() != expected[i] {
				t.Errorf("Sub() with mod index %v = %v, want %v", i, val, expected[i])
			}
		}
	})
}

func TestScale(t *testing.T) {
	t.Run("basic scaling", func(t *testing.T) {
		v := NewVec(3).Fill([]int64{1, 2, 3})
		scale := big.NewInt(2)
		mod := big.NewInt(100)

		result := v.Scale(scale, mod)
		expected := []int64{2, 4, 6}

		for i, val := range result.vec {
			if val.Int64() != expected[i] {
				t.Errorf("Scale() index %v = %v, want %v", i, val, expected[i])
			}
		}
	})

	t.Run("modular scaling", func(t *testing.T) {
		v := NewVec(3).Fill([]int64{4, 5, 6})
		scale := big.NewInt(3)
		mod := big.NewInt(10)

		result := v.Scale(scale, mod)
		expected := []int64{2, 5, 8} // (4*3)%10=2, (5*3)%10=5, (6*3)%10=8

		for i, val := range result.vec {
			if val.Int64() != expected[i] {
				t.Errorf("Scale() with mod index %v = %v, want %v", i, val, expected[i])
			}
		}
	})
}
