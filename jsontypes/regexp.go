package jsontypes

import (
	"encoding/json"
	"regexp"
)

type Regexp struct {
	*regexp.Regexp
}

func (r *Regexp) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return r.Unmarshal(s)
}

func (r *Regexp) Unmarshal(s string) (err error) {
	r.Regexp, err = regexp.Compile(s)
	return
}

func (r *Regexp) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Regexp.String())
}
