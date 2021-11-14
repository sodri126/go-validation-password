package validation

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPasswordValidation(t *testing.T) {
	t.Run("at_least_lower_case_alphabet_positive_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: false,
			AtLeastAlphabetLowerCase: true,
			AtLeastNumber:            false,
			AtLeastSpecialCharacter:  false,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("ABCDE12345a@#$")
		assert.Nil(t, err)
	})

	t.Run("at_least_lower_case_alphabet_negative_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: false,
			AtLeastAlphabetLowerCase: true,
			AtLeastNumber:            false,
			AtLeastSpecialCharacter:  false,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("ABD345!@#")
		assert.NotNil(t, err)
	})

	t.Run("at_least_upper_case_alphabet_positive_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: true,
			AtLeastAlphabetLowerCase: false,
			AtLeastNumber:            false,
			AtLeastSpecialCharacter:  false,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("abcdef12345A@#$")
		assert.Nil(t, err)
	})

	t.Run("at_least_upper_case_alphabet_negative_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: true,
			AtLeastAlphabetLowerCase: false,
			AtLeastNumber:            false,
			AtLeastSpecialCharacter:  false,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("abcdef345!@#")
		assert.NotNil(t, err)
	})

	t.Run("at_least_number_positive_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: false,
			AtLeastAlphabetLowerCase: false,
			AtLeastNumber:            true,
			AtLeastSpecialCharacter:  false,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("ABCdef1@#$")
		assert.Nil(t, err)
	})

	t.Run("at_least_number_negative_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: false,
			AtLeastAlphabetLowerCase: false,
			AtLeastNumber:            true,
			AtLeastSpecialCharacter:  false,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("abcABC!@#")
		assert.NotNil(t, err)
	})

	t.Run("at_least_special_character_default_positive_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: false,
			AtLeastAlphabetLowerCase: false,
			AtLeastNumber:            false,
			AtLeastSpecialCharacter:  true,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("abcABC123!")
		assert.Nil(t, err)
	})

	t.Run("at_least_special_character_default_negative_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: false,
			AtLeastAlphabetLowerCase: false,
			AtLeastNumber:            false,
			AtLeastSpecialCharacter:  true,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("abcABC123")
		assert.NotNil(t, err)
	})

	t.Run("at_least_special_character_custom_positive_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: false,
			AtLeastAlphabetLowerCase: false,
			AtLeastNumber:            false,
			AtLeastSpecialCharacter:  true,
			CustomSpecialCharacter:   "~",
		})

		err := password.CheckPassword("abc~LP")
		assert.Nil(t, err)
	})

	t.Run("at_least_special_character_custom_negative_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: false,
			AtLeastAlphabetLowerCase: false,
			AtLeastNumber:            false,
			AtLeastSpecialCharacter:  true,
			CustomSpecialCharacter:   "|",
		})

		err := password.CheckPassword("abcdef!@#$23")
		assert.NotNil(t, err)
	})

	t.Run("minimum_character_positive_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: true,
			AtLeastAlphabetLowerCase: true,
			AtLeastNumber:            true,
			AtLeastSpecialCharacter:  true,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("abcABC!2")
		assert.Nil(t, err)
	})

	t.Run("minimum_character_negative_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: true,
			AtLeastAlphabetLowerCase: true,
			AtLeastNumber:            true,
			AtLeastSpecialCharacter:  true,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("a")
		assert.NotNil(t, err)
	})

	t.Run("check_all_at_least_positive_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: true,
			AtLeastAlphabetLowerCase: true,
			AtLeastNumber:            true,
			AtLeastSpecialCharacter:  true,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("abcABC123!")
		assert.Nil(t, err)
	})

	t.Run("check_all_at_least_negative_case", func(t *testing.T) {
		password := New(&ParamPassword{
			MinimumCharacter:         5,
			AtLeastAlphabetUpperCase: true,
			AtLeastAlphabetLowerCase: true,
			AtLeastNumber:            true,
			AtLeastSpecialCharacter:  true,
			CustomSpecialCharacter:   "",
		})

		err := password.CheckPassword("abc1|")
		assert.NotNil(t, err)
	})
}
