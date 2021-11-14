package validation

import (
	"errors"
	"fmt"
)

const (
	dataAlphabetUpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	dataNumber            = "01234567789"
	specialCharacter      = "!@#$%^&*.-_"
	dataAlphabetLowerCase = "abcdefghijklmnopqrstuvwxyz"
)

var (
	ErrNoAlphabetUpperCaseCharacter = errors.New("error validation password: at least there is an alphabet uppercase character")
	ErrNoAlphabetLowerCaseCharacter = errors.New("error validation password: at least there is an alphabet lowercase character")
	ErrNoNumberCharacter            = errors.New("error validation password: at least there is an number character")
	ErrNoSpecialCharacter           = errors.New("error validation password: at least there is an special character (%s)")
	ErrMinLengthCharacter           = errors.New("error validation password: the minimum length of password is %d")
)

type password struct {
	minimumCharacter         int
	atLeastAlphabetUpperCase bool
	atLeastAlphabetLowerCase bool
	atLeastNumber            bool
	atLeastSpecialCharacter  bool
	customSpecialCharacter   string
	dataMapAlphabetUpperCase map[byte]bool
	dataMapAlphabetLowerCase map[byte]bool
	dataMapNumber            map[byte]bool
	dataMapSpecialCharacter  map[byte]bool
}

type ParamPassword struct {
	MinimumCharacter         int
	AtLeastAlphabetUpperCase bool
	AtLeastAlphabetLowerCase bool
	AtLeastNumber            bool
	AtLeastSpecialCharacter  bool
	CustomSpecialCharacter   string
}

type Password interface {
	CheckPassword(password string) (err error)
}

func New(param ...*ParamPassword) Password {
	// default parameter if user is not set the param
	pass := &ParamPassword{
		MinimumCharacter:         8,
		AtLeastAlphabetUpperCase: true,
		AtLeastAlphabetLowerCase: true,
		AtLeastNumber:            true,
		AtLeastSpecialCharacter:  true,
	}

	if len(param) > 0 {
		pass = param[0]
	}

	pass.setDefaultSpecialCharacter()
	pwd := &password{
		minimumCharacter:         pass.MinimumCharacter,
		atLeastAlphabetUpperCase: pass.AtLeastAlphabetUpperCase,
		atLeastAlphabetLowerCase: pass.AtLeastAlphabetLowerCase,
		atLeastNumber:            pass.AtLeastNumber,
		atLeastSpecialCharacter:  pass.AtLeastSpecialCharacter,
		customSpecialCharacter:   pass.CustomSpecialCharacter,
	}
	pwd.loadAllCharacters()
	return pwd
}

func (p *password) loadDataMapCharacter(character string) (data map[byte]bool) {
	data = make(map[byte]bool)
	for i := 0; i < len(character); i++ {
		data[character[i]] = true
	}
	return
}

// CheckPassword Complexity Check Password
// O(1)+O(Log N) = checkCharacter + CheckPassword
func (p *password) CheckPassword(password string) (err error) {
	err = p.minimumCharacterOn(password)
	if err != nil {
		return
	}

	flagAlphabetUpperCase, flagAlphabetLowerCase, flagNumber, flagSpecialCharacter := false, false, false, false
	if !p.atLeastAlphabetUpperCase {
		flagAlphabetUpperCase = true
	}
	if !p.atLeastAlphabetLowerCase {
		flagAlphabetLowerCase = true
	}
	if !p.atLeastNumber {
		flagNumber = true
	}
	if !p.atLeastSpecialCharacter {
		flagSpecialCharacter = true
	}
	for i := 0; i < len(password); i++ {
		chr := (password)[i]
		if !flagAlphabetUpperCase && p.dataMapAlphabetUpperCase[chr] {
			flagAlphabetUpperCase = true
		}
		if !flagAlphabetLowerCase && p.dataMapAlphabetLowerCase[chr] {
			flagAlphabetLowerCase = true
		}
		if !flagNumber && p.dataMapNumber[chr] {
			flagNumber = true
		}
		if !flagSpecialCharacter && p.dataMapSpecialCharacter[chr] {
			flagSpecialCharacter = true
		}
	}
	if !flagAlphabetUpperCase {
		err = ErrNoAlphabetUpperCaseCharacter
		return
	}
	if !flagAlphabetLowerCase {
		err = ErrNoAlphabetLowerCaseCharacter
		return
	}
	if !flagNumber {
		err = ErrNoNumberCharacter
		return
	}
	if !flagSpecialCharacter {
		err = fmt.Errorf(ErrNoSpecialCharacter.Error(), p.customSpecialCharacter)
	}
	return
}

func (p *password) loadAllCharacters() {
	if p.atLeastAlphabetUpperCase {
		p.dataMapAlphabetUpperCase = p.loadDataMapCharacter(dataAlphabetUpperCase)
	}
	if p.atLeastAlphabetLowerCase {
		p.dataMapAlphabetLowerCase = p.loadDataMapCharacter(dataAlphabetLowerCase)
	}
	if p.atLeastNumber {
		p.dataMapNumber = p.loadDataMapCharacter(dataNumber)
	}
	if p.atLeastSpecialCharacter {
		p.dataMapSpecialCharacter = p.loadDataMapCharacter(p.customSpecialCharacter)
	}
}

func (p *password) minimumCharacterOn(password string) (err error) {
	if len(password) < p.minimumCharacter {
		err = fmt.Errorf(ErrMinLengthCharacter.Error(), p.minimumCharacter)
	}
	return
}

func (c *ParamPassword) setDefaultSpecialCharacter() {
	if !c.AtLeastSpecialCharacter || c.CustomSpecialCharacter == "" {
		c.CustomSpecialCharacter = specialCharacter
	}
}
