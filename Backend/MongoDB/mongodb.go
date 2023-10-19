package mongodb_handler

import (
	"context"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Account struct {
	email     string
	password  string
	user_type string
}

type User struct {
	email string
	name  string
	dob   int
	phone string
}

type Admin struct {
	email string
	name  string
}

func Init_database(host string, port string, database string) *mongo.Database {
	// Set client options - Port, URL
	clientOptions := options.Client().ApplyURI("mongodb://" + host + ":" + port)

	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Println(err)
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Println(err)
	}

	fmt.Println("Connected to MongoDB!" + database)

	// Get a handle for your collection
	db := client.Database(database)
	return db
}

func Get_account(db *mongo.Database, email string) (map[string]interface{}, error) {
	filter := bson.D{{"email", email}}

	var result map[string]interface{}
	collection := db.Collection("account")
	err := collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		log.Println(err)
		return nil, err
	}

	fmt.Printf("Found a single document: %+v\n", result)

	return result, nil
}

// Insert a document into the database
func Create_account(db *mongo.Database, account map[string]interface{}) error {
	collection := db.Collection("account")
	new_account := account
	// hash password
	password := []byte(new_account["password"].(string))
	hash_password, err := bcrypt.GenerateFromPassword(password, 10)
	if err != nil {
		log.Println(err)
		return err
	}
	new_account["password"] = hash_password
	// save account
	insertResult, err := collection.InsertOne(context.TODO(), new_account)
	if err != nil {
		log.Println(err)
		return err
	}
	fmt.Println(insertResult)
	return nil
}

// Insert a document into the database
func insertUser(collection *mongo.Collection, user User) {
	insertResult, err := collection.InsertOne(context.TODO(), user)
	if err != nil {
		log.Println(err)
	}
	fmt.Println("Inserted a single document: ", insertResult.InsertedID)
}

// Insert multiple documents into the database
func insertMultipleUsers(collection *mongo.Collection, users []interface{}) {
	insertManyResult, err := collection.InsertMany(context.TODO(), users)
	if err != nil {
		log.Println(err)
	}
	fmt.Println("Inserted multiple documents: ", insertManyResult.InsertedIDs)
}

// Update a document in the database
func updateUser(collection *mongo.Collection, user User, userName string) {
	filter := bson.D{{"name", userName}}

	update := bson.D{
		{"$set", bson.D{{"user", user}}},
		{"$currentDate", bson.D{{"modifiedAt", true}}},
	}

	updateResult, err := collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Println(err)
	}
	fmt.Printf("Matched %v documents and updated %v documents.\n", updateResult.MatchedCount, updateResult.ModifiedCount)
}

// Find a document of the database
func findUser(collection *mongo.Collection, userName string) User {
	filter := bson.D{{"name", userName}}

	var result User

	err := collection.FindOne(context.TODO(), filter).Decode(&result)
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("Found a single document: %+v\n", result)

	return result
}

// Find all documents of a collection
func findAllUsers(collection *mongo.Collection) {
	findOptions := options.Find()
	findOptions.SetLimit(2)

	var results []User

	// Finding multiple documents returns a cursor
	cur, err := collection.Find(context.TODO(), bson.D{{}}, findOptions)
	if err != nil {
		log.Println(err)
	}

	// Iterate through the cursor
	for cur.Next(context.TODO()) {
		var elem User
		err := cur.Decode(&elem)
		if err != nil {
			log.Println(err)
		}

		results = append(results, elem)
	}

	if err := cur.Err(); err != nil {
		log.Println(err)
	}

	// Close the cursor once finished
	cur.Close(context.TODO())

	fmt.Printf("Found multiple documents (array of pointers): %+v\n", results)
}

// Delete a document of the database
func deleteAllUsers(collection *mongo.Collection) {
	deleteResult, err := collection.DeleteMany(context.TODO(), bson.D{{}})
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("Deleted %v documents in the users collection\n", deleteResult.DeletedCount)
}
