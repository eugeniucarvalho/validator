package validator

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Used by IsFilePath func
const (
	// Unknown is unresolved OS type
	Unknown = iota
	// Win is Windows type
	Win
	// Unix is *nix OS types
	Unix
)

var (
	RegexValidatorMap map[string]string
	// Map of validators
	ValidatorsFn = map[string]ValidateFn{
		"required": requiredFn,
		"len":      lenFn,
		//compare fields
		"eqf":  eqfieldFn,
		"nef":  nefieldFn,
		"gtf":  gtfieldFn,
		"gtef": gtefieldFn,
		"ltf":  ltfieldFn,
		"ltef": ltefieldFn,
		//compare values
		"eq": eqFn,
		"ne": neFn,

		"gt":  gtFn,
		"gte": gteFn,
		"lt":  ltFn,
		"lte": lteFn,

		"in":  inFn,
		"nin": ninFn,
		// time validators
		"after":  afterFn,
		"before": afterFn,
	}
)

func init() {

	URLSchema := `((ftp|tcp|udp|wss?|https?):\/\/)`
	URLUsername := `(\S+(:\S*)?@)`
	URLIP := `([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))`
	IP := `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
	URLSubdomain := `((www\.)|([a-zA-Z0-9]([-\.][-\._a-zA-Z0-9]+)*))`
	URLPort := `(:(\d{1,5}))`
	URLPath := `((\/|\?|#)[^\s]*)`

	RegexValidatorMap := map[string]string{
		"userRegexp":     "^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$",
		"hostRegexp":     "^[^\\s]+\\.[^\\s]+$",
		"userDotRegexp":  "(^[.]{1})|([.]{1}$)|([.]{2,})",
		"email":          "^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$",
		"creditCard":     "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$",
		"ISBN10":         "^(?:[0-9]{9}X|[0-9]{10})$",
		"ISBN13":         "^(?:[0-9]{13})$",
		"UUID3":          "^[0-9a-f]{8}-[0-9a-f]{4}-3[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$",
		"UUID4":          "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
		"UUID5":          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
		"UUID":           "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
		"alpha":          "^[a-zA-Z]+$",
		"alphanumeric":   "^[a-zA-Z0-9]+$",
		"numeric":        "^[0-9]+$",
		"int":            "^(?:[-+]?(?:0|[1-9][0-9]*))$",
		"float":          "^(?:[-+]?(?:[0-9]+))?(?:\\.[0-9]*)?(?:[eE][\\+\\-]?(?:[0-9]+))?$",
		"hexadecimal":    "^[0-9a-fA-F]+$",
		"hexcolor":       "^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$",
		"RGBcolor":       "^rgb\\(\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*,\\s*(0|[1-9]\\d?|1\\d\\d?|2[0-4]\\d|25[0-5])\\s*\\)$",
		"ASCII":          "^[\x00-\x7F]+$",
		"multibyte":      "[^\x00-\x7F]",
		"FullWidth":      "[^\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]",
		"HalfWidth":      "[\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]",
		"base64":         "^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$",
		"printableASCII": "^[\x20-\x7E]+$",
		"dataURI":        "^data:.+\\/(.+);base64$",
		"latitude":       "^[-+]?([1-8]?\\d(\\.\\d+)?|90(\\.0+)?)$",
		"longitude":      "^[-+]?(180(\\.0+)?|((1[0-7]\\d)|([1-9]?\\d))(\\.\\d+)?)$",
		"DNSName":        `^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*[\._]?$`,
		"IP":             IP,
		"URLSchema":      URLSchema,
		"URLUsername":    URLUsername,
		"URLPath":        URLPath,
		"URLPort":        URLPort,
		"URLIP":          URLIP,
		"URLSubdomain":   URLSubdomain,
		"URL":            `^` + URLSchema + `?` + URLUsername + `?` + `((` + URLIP + `|(\[` + IP + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + URLSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + URLPort + `?` + URLPath + `?$`,
		"SSN":            `^\d{3}[- ]?\d{2}[- ]?\d{4}$`,
		"WinPath":        `^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$`,
		"UnixPath":       `^(/[^/\x00]*)+/?$`,
		"Semver":         "^v?(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)(-(0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(\\.(0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(\\+[0-9a-zA-Z-]+(\\.[0-9a-zA-Z-]+)*)?$",
		"tagName":        "valid",
		"hasLowerCase":   ".*[[:lower:]]",
		"hasUpperCase":   ".*[[:upper:]]",
	}

	for k, regex := range RegexValidatorMap {
		AddRegexValidateFn(k, regex)
	}
}

func AddRegexValidateFn(name, regex string) {

	r := regexp.MustCompile(regex)

	ValidatorsFn[name] = func(i interface{}, o interface{}, v *ValidatorOption) error {
		if s, ok := i.(string); ok {

			if m := r.Match([]byte(s)); m || (s == "" && v.Optional) {
				return nil
			}
			return fmt.Errorf("O campo não apresenta um valor valido.")
		}
		return fmt.Errorf("O validador apenas é aplicado em campos do tipo texto.")
	}
}

func requiredFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {

	if IsEmpty(reflect.ValueOf(i)) {
		err = fmt.Errorf("O campo %s é obrigatório.", v.Attribute)
	}
	return
}

func lenFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {

	if IsEmpty(reflect.ValueOf(i)) {
		err = fmt.Errorf("O campo %s é obrigatório.", v.Attribute)
	}
	return
}

// func inFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {

// 	switch i.(type) {
// 	case string:
// 		vx := i.(string)
// 		for _, value := range v.Params {
// 			if value == vx {
// 				return nil
// 			}
// 		}
// 	}
// 	return
// }

func afterFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	return checkTimeFn(i, o, v, "a")
}

func beforeFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	return checkTimeFn(i, o, v, "b")
}

// default lyout "2006-01-02T15:04:05Z07:00"

func checkTimeFn(i interface{}, o interface{}, v *ValidatorOption, typ string) (err error) {
	var (
		t, base time.Time
		value   = v.Params[0]
		layout  = time.RFC3339
	)

	// Verifica se tem formato
	if len(v.Params) > 1 {
		layout = v.Params[1]
	}
	// determina o valor base
	if value == "now" {
		base = time.Now()
	} else if t1, e := time.Parse(layout, value); e == nil {
		base = t1
	} else {
		err = fmt.Errorf("Valor %s não pode ser convertido para time no formato %s", value, layout)
		return
	}

	switch i.(type) {
	case time.Time:
		t = i.(time.Time)

	case string:
		if t1, e := time.Parse(layout, value); e == nil {
			t = t1
		} else {
			err = fmt.Errorf("Valor %s não pode ser convertido para time no formato %s", i.(string), layout)
			return
		}

	case int, int8, int16, int32, int64:
		t = time.Unix(reflect.ValueOf(i).Int(), 0)

	default:
		err = fmt.Errorf("invalid field type for time validation")
		return
	}

	switch typ {
	case "a":
		if t.After(base) {
			return nil
		}
	case "b":
		if t.Before(base) {
			return nil
		}
	default:
		err = fmt.Errorf("time not after")
	}
	return
}

func eqfieldFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {

	p := Lookup(o, v.Params[0])

	if reflect.ValueOf(p).Kind() == reflect.ValueOf(i).Kind() {
		if p == i {
			return nil
		}
		return fmt.Errorf("Campo não possuem o mesmo valor")
	}

	return fmt.Errorf("Os campos não são do mesmo tipo. Comparando %s com %s", reflect.ValueOf(p).Kind().String(), reflect.ValueOf(i).Kind().String())
}

func nefieldFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {

	if e := eqfieldFn(i, o, v); e == nil {
		err = fmt.Errorf("Os campos não são do mesmo tipo.")
	}

	return
}

func gtfieldFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	p := Lookup(o, v.Params[0])
	res, e := compareField(i, p, ">")
	if e != nil {
		e = err
	} else if !res {
		err = fmt.Errorf("O valor informado é menor que o comparado")
	}
	return
}

func gtefieldFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {

	p := Lookup(o, v.Params[0])
	res, e := compareField(i, p, ">=")
	if e != nil {
		e = err
	} else if !res {
		err = fmt.Errorf("O valor informado é menor que o comparado")
	}
	return
}

func ltfieldFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	p := Lookup(o, v.Params[0])
	res, e := compareField(i, p, "<")
	if e != nil {
		e = err
	} else if !res {
		err = fmt.Errorf("O valor informado é maior que o comparado")
	}
	return
}

func ltefieldFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	p := Lookup(o, v.Params[0])
	res, e := compareField(i, p, "<=")
	if e != nil {
		e = err
	} else if !res {
		err = fmt.Errorf("O valor informado é maior que o comparado")
	}
	return
}

func compareField(i, p interface{}, op string) (bool, error) {
	// types.LookupFieldOrMethod()

	ri := reflect.ValueOf(i)
	rp := reflect.ValueOf(p)

	if rp.Kind() == ri.Kind() {
		switch rp.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:

			return compareInt(ri.Int(), rp.Int(), op), nil

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:

			return compareUint(ri.Uint(), rp.Uint(), op), nil
		case reflect.Float32, reflect.Float64:

			return compareFloat(ri.Float(), rp.Float(), op), nil
		case reflect.String:
			return compareString(i.(string), p.(string), op), nil
			// case reflect.Bool:
			// 	return compareBool(i.(bool), o.(bool), op)
		default:
			return false, fmt.Errorf("Field type not sortable. Accept types [string,int,uint,float]. Passed  type %s.", rp.Kind().String())
		}
	}
	return false, nil
}

// Verifica se o valor não pertence a lista de valores especificada.
func ninFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	if err := eqFn(i, o, v); err == nil {
		err = fmt.Errorf("O campo apresenta o mesmo valor")
	}
	return
}

func inFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {

	kind := reflect.ValueOf(i).Kind()
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Complex64, reflect.Complex128,
		reflect.Float32, reflect.Float64,
		reflect.Bool:

		value := fmt.Sprintf("%v", i)
		for _, v1 := range v.Params {
			if v1 == value {
				return nil
			}
		}
	default:
		err = fmt.Errorf("Field value '%s' not allowed on IN validador", kind.String())
	}
	return
}

// Compara o valor do campo com o valor determinado e verifica se são diferentes
func neFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	if err := eqFn(i, o, v); err == nil {
		err = fmt.Errorf("O campo apresenta o mesmo valor")
	}
	return
}

// Compara o valor do campo convertido para string com o valor especificado no parametro do validador
func eqFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	switch len(v.Params) {
	case 0:
		panic("LteFN param not defined.")
	default:
		if !(fmt.Sprintf("%v", i) == strings.Trim(v.Params[0], "")) {
			err = fmt.Errorf("O valor informado é diferente do comparado")
		}
	}
	return
}

func gtFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	return compareSortableField(i, o, v, ">")
}
func gteFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	return compareSortableField(i, o, v, ">=")
}
func ltFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	return compareSortableField(i, o, v, "<")
}
func lteFn(i interface{}, o interface{}, v *ValidatorOption) (err error) {
	return compareSortableField(i, o, v, "<=")
}

func compareSortableField(i interface{}, o interface{}, v *ValidatorOption, op string) (err error) {
	var (
		vf    float64
		vi    int64
		value = v.Params[0]
		vr    = reflect.ValueOf(i)
	)
	switch vr.Kind() {
	case reflect.Float32, reflect.Float64:
		if vf, err = strconv.ParseFloat(value, 64); err != nil {
			return
		}
		if compareFloat(vr.Float(), vf, op) {
			return
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if vi, err = strconv.ParseInt(value, 10, 64); err != nil {
			return
		}
		if compareInt(vr.Int(), vi, op) {
			return
		}
	default:
		return fmt.Errorf("O tipo '%s' não é comparavel", vr.Kind().String())
	}
	return fmt.Errorf("Os valores comparados apresentam erro")
}

func compareString(v1, v2 string, op string) bool {
	switch op {
	case ">":
		return v1 > v2
	case ">=":
		return v1 >= v2
	case "<":
		return v1 < v2
	case "<=":
		return v1 <= v2
	default:
		return false
	}
}

func compareUint(v1, v2 uint64, op string) bool {
	switch op {
	case ">":
		return v1 > v2
	case ">=":
		return v1 >= v2
	case "<":
		return v1 < v2
	case "<=":
		return v1 <= v2
	default:
		return false
	}
}

func compareFloat(v1, v2 float64, op string) bool {
	switch op {
	case ">":
		return v1 > v2
	case ">=":
		return v1 >= v2
	case "<":
		return v1 < v2
	case "<=":
		return v1 <= v2
	default:
		return false
	}
}

func compareInt(v1, v2 int64, op string) bool {
	switch op {
	case ">":
		return v1 > v2
	case ">=":
		return v1 >= v2
	case "<":
		return v1 < v2
	case "<=":
		return v1 <= v2
	default:
		return false
	}
}
