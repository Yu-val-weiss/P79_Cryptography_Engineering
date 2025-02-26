package sigma

import "testing"

func TestNewBaseClient(t *testing.T) {
	name := "alice"
	c := NewBaseClient(name)
	if c.Name != name {
		t.Errorf("expected name to be %v, was %v", name, c.Name)
	}
}
