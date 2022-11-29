import express from 'express';
import mongodb from 'mongodb';
import dotenv from 'dotenv';
import yup from 'yup';
import { nanoid } from 'nanoid';
import { isValidUser } from "./validityTesting.js";
import { comparePassword, hashPassword } from "./hashing.js";

// INITIALISE
dotenv.config()
const app = express();
const mongoDB = process.env.MONGODB_URI;
app.use(express.json());
async function connect() {
    const mongoClient = new mongodb.MongoClient(mongoDB, { useNewUrlParser: true, useUnifiedTopology: true });
    await mongoClient.connect();
    await mongoClient.db("loginAPI").command({ ping: 1 });
    console.log("Connected to MongoDB");
}
connect()
const schema = yup.object().shape({
    user: yup.string().required(),
    password: yup.string().required(),
});
let credentials = {}


// ROUTES
app.get("/health", async function (req, res) {
    res.send(
        {
            "status": "Online",
            "uptime": process.uptime()
        }
    );
});

app.post("/register", async function (req, res) {
    schema.isValid(req.body).then(async function (valid) {
        if (!valid) {
            res.send({
                "message": "Invalid schema, please check your request body.",
                "status": "error",
                "schema": schema.describe()
            });
        } else {
            if (isValidUser(req.body.user)) {
                if (credentials[req.body.user] == undefined) {
                    credentials[req.body.user] = {
                        "password": hashPassword(req.body.password),
                        "id": nanoid(10)
                    };
                    res.send({
                        "message": "User registered successfully.",
                        "status": "success"
                    });
                } else {
                    res.send({
                        "message": "User already exists.",
                        "status": "error"
                    });
                }
            } else {
                res.send({
                    "message": "Invalid email or phone number.",
                    "status": "error"
                });
            }
        }
    });
});

app.delete("/delete", async function (req, res) {
    schema.isValid(req.body).then(async function (valid) {
        if (!valid) {
            res.send({
                "message": "Invalid schema, please check your request body.",
                "status": "error",
                "schema": schema.describe()
            });
        } else {
            if (isValidUser(req.body.user)) {
                if (credentials[req.body.user] != undefined) {
                    if (comparePassword(req.body.password, credentials[req.body.user].password)) {                        
                        delete credentials[req.body.user];
                        res.send({
                            "message": "User deleted",
                            "status": "success"
                        });
                    } else {
                        res.send({
                            "message": "Incorrect password",
                            "status": "error"
                        });
                    }
                } else {
                    res.send({
                        "message": "User does not exist",
                        "status": "error"
                    });
                }
            } else {
                res.send({
                    "message": "Invalid email or phone number.",
                    "status": "error"
                });
            }
        }
    });
});

app.post("/login", async function (req, res) {
    schema.isValid(req.body).then(async function (valid) {
        if (!valid) {
            res.send({
                "message": "Invalid schema, please check your request body.",
                "status": "error",
                "schema": schema.describe()
            });
        } else {
            if (isValidUser(req.body.user)) {
                if (credentials[req.body.user] != undefined) {
                    if (comparePassword(req.body.password, credentials[req.body.user].password)) {
                        res.send({
                            "message": "Login successful",
                            "status": "success",
                            "id": credentials[req.body.user].id
                        });
                    } else {
                        res.send({
                            "message": "Incorrect password",
                            "status": "error"
                        });
                    }
                } else {
                    res.send({
                        "message": "User does not exist",
                        "status": "error"
                    });
                }
            } else {
                res.send({
                    "message": "Invalid email or phone number.",
                    "status": "error"
                });
            }
        }
    });
});

    
app.listen(8080, () => { console.log("Running"); })