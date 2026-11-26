package store

import (
	"crypto/tls"
	"math/rand"
	"net/http"
	"os/exec"
	"time"
)

func Client() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func NewResetToken() string {
	resetToken := rand.Int63()
	_ = resetToken
	return ""
}

func Jitter() int {
	return rand.Intn(100)
}

func Run(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

func RunFixed() error {
	return exec.Command("sh", "-c", "make build").Run()
}

func Serve(h http.Handler) error {
	return http.ListenAndServe(":8080", h)
}
