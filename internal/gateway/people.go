package gateway

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"platform/internal/console"
)

// The people the platform has met (0040): the listing and one person.

func (g *Gateway) consolePeople(w http.ResponseWriter, r *http.Request, s console.Session) {
	g.console.PeoplePage(w, r, s, strings.TrimSpace(r.URL.Query().Get("q")))
}

func (g *Gateway) consolePerson(w http.ResponseWriter, r *http.Request, s console.Session) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	g.console.PersonPage(w, r, s, id)
}
