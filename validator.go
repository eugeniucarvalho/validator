package validator

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
)

const (
	TAG_NAME = "valid"
)

var (
	ignoreValidRegex = regexp.MustCompile("^-$")

	// validateRegex = regexp.MustCompile(`(?P<validator>\w+(\((\"\w+\"|\w+\??) (,(\"\w+\"|\w+\??))* \)|\s*))`)
	validateRegex = regexp.MustCompile(`(?P<validator>\w+(\((\".*\"|.*) (,(\".*\"|.*))* \)|\s*))`)
)

type ValidateFn func(i interface{}, o interface{}, v *ValidatorOption) error

type Validator struct {
	Wg           sync.WaitGroup
	Errors       []*Error
	ValidatorsFn map[string]ValidateFn
}

type ValidatorOption struct {
	ID        string
	Attribute string
	Optional  bool
	Params    []string
	Fn        ValidateFn
}

func (t *Validator) AddError(e *Error) *Validator {
	t.Errors = append(t.Errors, e)
	return t
}

func (t *ValidatorOption) Exec(val, valueField reflect.Value) (err *Error) {

	var (
		value interface{}
	)

	if valueField.CanInterface() {
		value = valueField.Interface()
	} else {
		value = valueField
	}

	if errf := t.Fn(value, val.Interface(), t); errf != nil {

		err = &Error{
			Validator: t.ID,
			Attribute: t.Attribute,
			Message:   errf.Error(),
		}
	}
	return
}

type Error struct {
	Message   string
	Attribute string
	Validator string
}

type Errors []Error

func Struct(s interface{}) ([]*Error, bool) {
	v := New()
	rs := reflect.ValueOf(s)

	v.structField(rs, rs, "")

	v.Wg.Wait()

	if len(v.Errors) == 0 {
		return nil, true
	}
	return v.Errors, false
}

func (v *Validator) structField(val, stru reflect.Value, fieldName string) {

	v.Wg.Add(1)

	defer func() {
		// time.Sleep(500 * time.Millisecond)
		// fmt.Println("Encerrando validadao ", fieldName)
		v.Wg.Done()
	}()

	switch stru.Kind() {

	case reflect.Interface, reflect.Ptr:
		stru = stru.Elem()
		fallthrough
	case reflect.Struct:

		typ := stru.Type()

		// fmt.Println("Numero de campos", stru.NumField())
		// spew.Dump(typ)

		for index := 0; index < stru.NumField(); index += 1 {

			v.Wg.Add(1)
			go func(valueField reflect.Value, typeField reflect.StructField) {
				//	fmt.Println("Iniciando validação do campo", typeField.Name)
				// val - the struct
				// fmt.Println(typeField.Name, typeField.Anonymous)

				// spew.Dump(valueField)
				// spew.Dump(typeField)

				v.field(val, valueField, typeField, typeField.Name)

			}(stru.Field(index), typ.Field(index))
		}

	default:
		v.AddError(&Error{
			Attribute: fieldName,
			Validator: "struct",
			Message:   fmt.Sprintf("Only structs are accept; got %s", val.Kind()),
		})
	}
}

func (v *Validator) ParseTag(tag, attribute string) []ValidatorOption {

	var (
		id       string
		fn       ValidateFn
		declared bool
	)

	validators := []ValidatorOption{}

	for _, part := range strings.Split(tag, ";") {

		if !validateRegex.Match([]byte(part)) {
			continue
		}

		matchs := validateRegex.FindAllString(part, -1)
		id = matchs[0]

		if fn, declared = v.GetValidatorFn(id); !declared {

		}

		validators = append(validators, ValidatorOption{
			ID:        id,
			Attribute: attribute,
			Params:    matchs[1:],
			Fn:        fn,
			Optional:  part[len(part)-1] == '?',
		})

	}
	return validators
}

func appendPathName(base, new string, array bool) string {
	conector := ""

	if base != "" {
		if array {
			conector = ".$."
		} else {
			conector = "."
		}
	}

	return base + conector + new
}

func (v *Validator) field(val, valueField reflect.Value, typeField reflect.StructField, fieldName string) {
	// v.Wg.Add(1)

	defer func() {
		fmt.Println("Encerrando validador do campo", fieldName)
		v.Wg.Done()
	}()

	var (
		// array                = false
		err                  *Error
		name                 = typeField.Name
		tagValue, tagDefined = typeField.Tag.Lookup(TAG_NAME)
	)

	// fmt.Println(tagDefined, tagValue)
	// Private field or ignore field
	if !tagDefined || typeField.PkgPath != "" || ignoreValidRegex.MatchString(tagValue) {
		fmt.Println("Campo foi ignorado ", fieldName)
		return
	}
	// Se o atributo for uma struct embedded
	if typeField.Anonymous {
		name = ""
	}
	name = appendPathName(fieldName, name, false)

	// fieldName += "." + typeField.Name

	fmt.Println("validate field:", typeField.Name, valueField)

	switch valueField.Kind() {
	// is a pointer to one
	case reflect.Ptr:
		// case reflect.Interface:
		// if is struct
		switch valueField.Elem().Kind() {
		case reflect.Struct:
			// fmt.Println("valid field ptr struc", typeField.Name, appendPathName(fieldName, name, array))
			v.structField(val, valueField.Elem(), name)

		case reflect.Slice, reflect.Array:
			// fmt.Println("valid field ptr slice")
			name = appendPathName(fieldName, name, true)
			v.arrayField(val, valueField.Elem(), name)
		}
	case reflect.Struct:
		// fmt.Println("valid field struct", typeField.Name, appendPathName(fieldName, name, array))

		v.structField(val, valueField, name)

	case reflect.Slice, reflect.Array:
		// fmt.Println("valid field slice", typeField.Name)
		name = appendPathName(fieldName, name, true)
		v.arrayField(val, valueField, name)

	// case reflect.Interface:
	// 	// If the value is an interface then encode its element
	// 	// fmt.Println("Era interface")
	// 	if valueField.IsNil() {

	// 	}
	default:
	}

	// fmt.Println("path name:", name)
	validations := v.ParseTag(tagValue, name)

	for _, vldt := range validations {

		if err = vldt.Exec(val, valueField); err != nil {
			fmt.Println("erro test validador", vldt.ID, fieldName, valueField)
			v.AddError(err)
		}
	}
}

func Array(s interface{}) []*Error {
	rs := reflect.ValueOf(s)
	return New().array(rs, rs, "")
}

func (v *Validator) array(val, itens reflect.Value, fieldName string) []*Error {

	v.arrayField(val, itens, fieldName)

	if len(v.Errors) == 0 {
		return nil
	}
	return v.Errors
}

func (v *Validator) arrayField(val, itens reflect.Value, fieldName string) {

	switch itens.Kind() {

	case reflect.Array, reflect.Slice:
		for i := 0; i < itens.Len(); i++ {
			go func(item reflect.Value) {
				switch item.Kind() {
				// caso o array seja de struct -> executa a validacao de cada struct
				case reflect.Struct:
					v.structField(val, reflect.Indirect(item), fieldName)
				default:
				}
			}(itens.Index(i))
		}

	default:
		v.AddError(&Error{
			Attribute: fieldName,
			Message:   "Itens not is a slice",
		})
		// valid = false
	}

	// return valid, v.Errors
}

func RegisterValidator(id string, fn ValidateFn) error {
	if id == "" {
		return fmt.Errorf("Validator id not accept the empty value.")
	}

	if fn == nil {
		return fmt.Errorf("Validation fn not accept the nil fn.")
	}
	ValidatorsFn[id] = fn
	return nil
}

func IsEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String, reflect.Array:
		return v.Len() == 0
	case reflect.Map, reflect.Slice:
		return v.Len() == 0 || v.IsNil()
	// case reflect.Bool:
	// 	return !v.Bool()
	// case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	// 	return v.Int() == 0
	// case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
	// 	return v.Uint() == 0
	// case reflect.Float32, reflect.Float64:
	// 	return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
}

func New() *Validator {
	return &Validator{
		Wg: sync.WaitGroup{},
	}
}

func (t *Validator) Declared(validator string) bool {
	_, declared := ValidatorsFn[validator]
	return declared
}
func (t *Validator) GetValidatorFn(validator string) (ValidateFn, bool) {
	fn, declared := ValidatorsFn[validator]
	return fn, declared
}

// resultField, err2 := typeCheck(valueField, typeField, val, nil)
// if err2 != nil {

// 	// Replace structure name with JSON name if there is a tag on the variable
// 	jsonTag := toJSONName(typeField.Tag.Get("json"))
// 	if jsonTag != "" {
// 		switch jsonError := err2.(type) {
// 		case Error:
// 			jsonError.Name = jsonTag
// 			err2 = jsonError
// 		case Errors:
// 			for i2, err3 := range jsonError {
// 				switch customErr := err3.(type) {
// 				case Error:
// 					customErr.Name = jsonTag
// 					jsonError[i2] = customErr
// 				}
// 			}

// 			err2 = jsonError
// 		}
// 	}

// 	errs = append(errs, err2)
// }
// result = result && resultField && structResult
