package jsontypes

import (
	"encoding/json"
	"time"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return d.Unmarshal(s)
}

func (d *Duration) Unmarshal(s string) (err error) {
	d.Duration, err = time.ParseDuration(s)
	return
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}
