// Package web holds the demo pages and the pinned altcha widget (3.5.0 with all its UI
// translations, dist/main/altcha.i18n.min.js from the v3.5.0 tag, MIT, see LICENSE-altcha.txt).
// The demo inlines the widget into the page, as banjax does: no CDN.
package web

import (
	"embed"
	"html/template"
)

//go:embed *.html altcha-3.5.0.i18n.min.js
var files embed.FS

// Baskerville is the sniffing dog on the challenge page.
//
//go:embed baskerville.gif
var Baskerville []byte

// Widget is the altcha@3.5.0 i18n bundle, to inline in a <script type="module">.
var Widget template.JS

// Pages are the demo pages, each executed by its file name: index.html, challenge.html,
// granted.html. They share layout.html.
var Pages = map[string]*template.Template{}

func init() {
	b, err := files.ReadFile("altcha-3.5.0.i18n.min.js")
	if err != nil {
		panic(err)
	}
	Widget = template.JS(b)
	for _, name := range []string{"index.html", "challenge.html", "granted.html"} {
		Pages[name] = template.Must(template.ParseFS(files, "layout.html", name))
	}
}
