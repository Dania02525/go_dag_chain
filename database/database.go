package database

import (
    "fmt"
    "github.com/cockroachdb/pebble"
)

var Database *pebble.Db
var Sync pebble.Sync
var NotFound pebble.ErrNotFound

func Connect() {
    Database, err := pebble.Open("chain", &pebble.Options{})
    if err != nil {
        panic(err)
    } else {
        fmt.Println("Successfully connected to the database")
    }
}
