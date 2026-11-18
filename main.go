package main

import (
	"net/http"
	"annot/pkg/handlers"
)

func main() {
	http.HandleFunc("/handle00", handlers.Handle00)
	http.HandleFunc("/handle01", handlers.Handle01)
	http.HandleFunc("/handle02", handlers.Handle02)
	http.HandleFunc("/handle03", handlers.Handle03)
	http.HandleFunc("/handle04", handlers.Handle04)
	http.HandleFunc("/handle05", handlers.Handle05)
	http.HandleFunc("/handle06", handlers.Handle06)
	http.HandleFunc("/handle07", handlers.Handle07)
	http.HandleFunc("/safehandle08", handlers.SafeHandle08)
	http.HandleFunc("/safehandle09", handlers.SafeHandle09)
	http.HandleFunc("/safehandle10", handlers.SafeHandle10)
	http.HandleFunc("/safehandle11", handlers.SafeHandle11)
	http.HandleFunc("/safehandle12", handlers.SafeHandle12)
	http.HandleFunc("/safehandle13", handlers.SafeHandle13)
	http.ListenAndServe(":8080", nil)
}
