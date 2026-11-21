package web

import (
	"testing"

	webassets "github.com/dameyerdave/privnet/web"
)

// Templates must parse; execution errors are covered by the smoke test.
func TestTemplatesParse(t *testing.T) {
	s := &Server{}
	if err := s.loadTemplates(webassets.FS); err != nil {
		t.Fatal(err)
	}
}
