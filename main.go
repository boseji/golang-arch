package main

import (
	"context"
	"log"
	"net/url"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {

	// 0. Get All Parameters
	username := url.QueryEscape(os.Getenv("MONGO_USER"))
	password := url.QueryEscape(os.Getenv("MONGO_PASS"))
	host := url.QueryEscape(os.Getenv("MONGO_HOST"))
	connOpt := os.Getenv("MONGO_CONNECTION_OPTIONS")
	dbName := os.Getenv("MONGO_DB")

	// 1. Create the URI for Mongo DB
	uri := "mongodb+srv://" + username + ":" + password + "@" + host + "/"
	// If there are any additional options for the URI
	if connOpt != "" {
		uri += "?" + connOpt
	}

	// 2. Get the Client
	opt := options.Client().ApplyURI(uri)
	client, err := mongo.NewClient(opt)
	if err != nil {
		log.Fatal(err)
	}

	// Context to Timeout if the request does not return within 10 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 3. Connect to the Client using a Timeout Context
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	// 4. Get to Collection in DB
	coll := client.Database(dbName).Collection("users")

	// 5. Query the Collection for All records
	cursor, err := coll.Find(ctx, bson.D{})
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(ctx)

	// 6. Loop through the data and Print it
	for cursor.Next(ctx) {
		log.Println("Record -", cursor.Current.String())
	}
}
