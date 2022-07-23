package main

import (
	"log"
)

func main() {

	server, err := CreateServer()
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(server.StartApp())
}
