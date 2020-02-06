package anonymiser

import (
	"errors"
	"fmt"
	"reflect"
)

// dc avem un tip, cu marcaje specifice
// vrem sa cream o copie anonimizata, conform marcajelor
//
type Config map[string]interface{}

func (c Config) Anonymise(obj interface{}) (interface{}, error) {
	ov := reflect.ValueOf(obj)
	oc, err := c.anonymise(ov)
	if err != nil {
		return nil, err
	}
	return oc.Interface(), nil
}

func (c Config) anonymise(ov reflect.Value) (reflect.Value, error) {
	if !ov.IsValid() {
		return reflect.Value{}, errors.New("invalid value")
	}

	if t := ov.Type(); t.PkgPath() == "time" && t.Name() == "Time" {
		return c.anonymiseTime(ov)
	}
	switch ov.Kind() {
	case reflect.Struct:
		return c.anonymiseStruct(ov)
	case reflect.Ptr:
		return c.anonymisePointer(ov)
	case reflect.Slice:
		return c.anonymiseSlice(ov)
	case reflect.Map:
		return c.anonymiseMap(ov)
	case reflect.Interface:
		return c.anonymiseInterface(ov)
	case reflect.Array:
		return c.anonymiseArray(ov)
	case reflect.Int, reflect.String, reflect.Int64, reflect.Float64, reflect.Bool, reflect.Uint, reflect.Uint64,
		reflect.Func, reflect.Chan, reflect.Float32,
		reflect.Int8, reflect.Int16, reflect.Int32,
		reflect.Complex64, reflect.Complex128,
		reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return ov, nil
	}
	panic(fmt.Sprintf("unsupported type: %s", ov.Kind()))
}

func (c Config) anonymiseStruct(ov reflect.Value) (reflect.Value, error) {
	oc := reflect.New(ov.Type()).Elem()
	ot := ov.Type()
	for i := 0; i < ot.NumField(); i++ {
		// skip unexported fields
		if !ov.Field(i).CanInterface() {
			continue
		}
		tag := ot.Field(i).Tag.Get("anonymise")
		if tag == "" {
			// cannot set zero values, in case of pointers
			if v, err := c.anonymise(ov.Field(i)); err != nil {
				return reflect.Zero(ov.Type()), err
			} else if !v.IsZero() {
				oc.Field(i).Set(v)
			}
		} else {
			fn := c[tag]
			if fn == nil {
				return reflect.Zero(ov.Type()), fmt.Errorf("missing anonymiser for: %s", tag)
			}
			values := reflect.ValueOf(fn).Call([]reflect.Value{ov.Field(i)})
			// cannot set zero values, in case of pointers
			if !values[0].IsZero() {
				oc.Field(i).Set(values[0])
			}
		}
	}
	return oc, nil
}

func (c Config) anonymisePointer(ov reflect.Value) (reflect.Value, error) {
	if ov.IsNil() {
		return ov, nil
	}
	oc := reflect.New(ov.Type().Elem())
	v, err := c.anonymise(ov.Elem())
	if err != nil {
		return reflect.Zero(ov.Type()), err
	}
	if !v.IsZero() {
		oc.Elem().Set(v)
	}
	return oc, nil
}

func (c Config) anonymiseInterface(ov reflect.Value) (reflect.Value, error) {
	if ov.IsNil() {
		return ov, nil
	}
	oc := reflect.New(ov.Type()).Elem()
	v, err := c.anonymise(ov.Elem())
	if err != nil {
		return reflect.Zero(ov.Type()), err
	}
	oc.Set(v)
	return oc, nil
}

func (c Config) anonymiseSlice(ov reflect.Value) (reflect.Value, error) {
	if ov.IsNil() {
		return ov, nil
	}
	oc := reflect.MakeSlice(ov.Type(), 0, ov.Len())
	for i := 0; i < ov.Len(); i++ {
		v, err := c.anonymise(ov.Index(i))
		if err != nil {
			return reflect.Zero(ov.Type()), err
		}
		oc = reflect.Append(oc, v)
	}
	return oc, nil
}

func (c Config) anonymiseArray(ov reflect.Value) (reflect.Value, error) {
	oc := reflect.New(ov.Type()).Elem()
	slice := oc.Slice3(0, 0, ov.Len())
	for i := 0; i < ov.Len(); i++ {
		v, err := c.anonymise(ov.Index(i))
		if err != nil {
			return reflect.Zero(ov.Type()), err
		}
		slice = reflect.Append(slice, v)
	}
	return oc, nil
}

func (c Config) anonymiseMap(ov reflect.Value) (reflect.Value, error) {
	if ov.IsNil() {
		return ov, nil
	}
	oc := reflect.MakeMapWithSize(ov.Type(), ov.Len())
	iter := ov.MapRange()
	for iter.Next() {
		k, err := c.anonymise(iter.Key())
		if err != nil {
			return reflect.Zero(ov.Type()), err
		}
		v, err := c.anonymise(iter.Value())
		if err != nil {
			return reflect.Zero(ov.Type()), err
		}
		oc.SetMapIndex(k, v)
	}
	return oc, nil
}

func (c Config) anonymiseTime(ov reflect.Value) (reflect.Value, error) {
	return ov, nil
}
