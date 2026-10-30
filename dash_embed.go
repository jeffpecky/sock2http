package main

import _ "embed"

// dashboardHTML is embedded from dashboard.html at build time and served at
// http://127.0.0.1:<laddr>/admin, so a non-technical user gets the console
// from the same process that runs the proxy.
//
//go:embed dashboard.html
var dashboardHTML string
