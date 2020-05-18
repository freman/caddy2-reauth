package jsontypes

import (
	"encoding/json"
	"net/url"
)

type URL struct {
	*url.URL
}

func (u URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.URL.String())
}

func (u *URL) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return u.Unmarshal(s)
}

func (u *URL) Unmarshal(s string) (err error) {
	u.URL, err = url.Parse(s)
	return
}
