package validator

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// ToString convert the input to a string.
func ToString(obj interface{}) string {
	res := fmt.Sprintf("%v", obj)
	return string(res)
}

// ToJSON convert the input to a valid JSON string
func ToJSON(obj interface{}) (string, error) {
	res, err := json.Marshal(obj)
	if err != nil {
		res = []byte("")
	}
	return string(res), err
}

// ToFloat convert the input string to a float, or 0.0 if the input is not a float.
func ToFloat(str string) (float64, error) {
	res, err := strconv.ParseFloat(str, 64)
	if err != nil {
		res = 0.0
	}
	return res, err
}

// ToInt convert the input string or any int type to an integer type 64, or 0 if the input is not an integer.
func ToInt(value interface{}) (res int64, err error) {
	val := reflect.ValueOf(value)

	switch value.(type) {
	case int, int8, int16, int32, int64:
		res = val.Int()
	case uint, uint8, uint16, uint32, uint64:
		res = int64(val.Uint())
	case string:
		// if IsInt(val.String()) {
		// res, err = strconv.ParseInt(val.String(), 0, 64)
		return strconv.ParseInt(val.String(), 0, 64)
		// if err != nil {
		// 	res = 0
		// }
		// } else {
		// 	err = fmt.Errorf("math: square root of negative number %g", value)
		// 	res = 0
		// }
	default:
		err = fmt.Errorf("math: square root of negative number %g", value)
		res = 0
	}

	return
}

// ToBoolean convert the input string to a boolean.
func ToBoolean(str string) (bool, error) {
	return strconv.ParseBool(str)
}

func Lookup(s interface{}, path string) interface{} {
	return lkp(reflect.ValueOf(s), strings.Split(path, "."))
}

func lkp(s reflect.Value, path []string) interface{} {
	var ret reflect.Value
	switch s.Kind() {

	case reflect.Ptr:
		return lkp(s.Elem(), path)

	case reflect.Map:
		ret = s.MapIndex(reflect.ValueOf(path[0]))

	case reflect.Struct:
		ret = s.FieldByName(path[0])
	}

	if ret == reflect.Zero(s.Type()) {
		return nil

	} else if len(path) > 1 {
		return lkp(ret, path[1:])

	} else if ret.CanInterface() {

		return ret.Interface()
	} else {

		return ret
	}

}
