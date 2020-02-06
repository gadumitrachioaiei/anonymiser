package anonymiser

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type A struct {
	Data []string `anonymise:"AnonymiseData"`
}

type T struct {
	Data A
	Name string `anonymise:"AnonymiseName"`
	C    int
	D    *A
}

func AnonymiseName(name string) string {
	return "not important"
}

func AnonymiseData(data []string) []string {
	return []string{"not " + data[0]}
}

func TestAnonymise(t *testing.T) {
	c := Config{"AnonymiseName": AnonymiseName, "AnonymiseData": AnonymiseData}
	u := T{Name: "important", C: 1, Data: A{Data: []string{"important"}}}
	vi, err := c.Anonymise(u)
	if err != nil {
		t.Fatal(err)
	}
	v := vi.(T)
	if v.Name != AnonymiseName(u.Name) {
		t.Fatalf("got name: %s, expected: %s", v.Name, u.Name)
	}
	if diff := cmp.Diff(v.Data.Data, AnonymiseData(u.Data.Data)); diff != "" {
		t.Fatal(diff)
	}
	v.Name = u.Name
	v.Data.Data = u.Data.Data
	if diff := cmp.Diff(v, u); diff != "" {
		t.Fatal(diff)
	}
}

func TestAnonymiseNil(t *testing.T) {
	var x *int
	c := Config{}
	vi, err := c.Anonymise(x)
	if err != nil {
		t.Fatal(err)
	}
	v := vi.(*int)
	if v != nil {
		t.Fatalf("got value: %v, expected nil", v)
	}
}

func TestAnonymiseNilField(t *testing.T) {
	fn := func(a *int) *int {
		x := 1
		return &x
	}
	type T struct {
		A *int `anonymise:"fn"`
	}
	c := Config{"fn": fn}
	vi, err := c.Anonymise(T{})
	if err != nil {
		t.Fatal(err)
	}
	v := vi.(T)
	if v.A == nil || *v.A != 1 {
		t.Fatalf("got value: %v, expected int pointer to 1", v)
	}
}
