package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	p, err := NewPool(4, time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		log.Fatal(http.ListenAndServe(":8080", p))
	}()
	<-c
	p.Flush()
}
