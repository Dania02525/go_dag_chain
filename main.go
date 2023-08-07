package main

import (
    "go-metering/database"
    "go-metering/model"
    "github.com/joho/godotenv"
    "log"
)

func main() {
    loadEnv()
    loadDatabase()
    err := model.InitChain()
    if err != nil {
    	log.Fatal(err)
    }
}

func loadDatabase() {
    database.Connect()
    // automigrate does not work
    //database.Database.Debug().AutoMigrate(&model.Block{})
    database.Database.Debug().Migrator().DropTable(&model.Block{})
    database.Database.Debug().Migrator().CreateTable(&model.Block{})
}

func loadEnv() {
    err := godotenv.Load(".env.local")
    if err != nil {
        log.Fatal("Error loading .env file")
    }
}
