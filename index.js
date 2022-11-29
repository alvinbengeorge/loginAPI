import express from 'express';
import mongodb from 'mongodb';
import dotenv from 'dotenv';
import { nanoid } from 'nanoid';
import { comparePassword, hashPassword, isValidUser, generateToken, verifyToken, updateSchema, checkSchema } from "./security.js";

const app = express();
app.use(express.json())
dotenv.config()
const client = new mongodb.MongoClient(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true });

async function connectMongo() {
    await client.connect();
    console.log("Connected to MongoDB");
}
connectMongo();

const db = client.db('loginAPI');

app.get("/health", async function (req, res) {
    res.status(200).send(
        {
            "status": "OK",
            "uptime": process.uptime()
        }
    );
});

app.post("/register", async function (req, res) {
    if (checkSchema(req, res)) {
        const user = req.body.user;
        const password = req.body.password;
        const found = await db.collection('login').findOne(
            { "user": user }
        )
        if (isValidUser(user) && !found) {
            const hashedPassword = await hashPassword(password);
            const result = await db.collection('login').insertOne(
                {
                    "user": user,
                    "password": hashedPassword,
                    "userID": nanoid()
                }
            );
            console.log("User Created ", user)
            res.status(200).send(
                {
                    "message": "User created",
                    "userID": result.userID
                }
            );
        } else if (found) {
            res.status(400).send(
                { "message": "User Already exists" }
            )
        } else {
            res.status(400).send(
                { "message": "Invalid user" }
            );
        }
    }
});

app.post("/login", async function (req, res) {
    if (checkSchema(req, res)) {
        const user = req.body.user;
        const password = req.body.password;
        if (isValidUser(user)) {
            const result = await db.collection('login').findOne(
                { "user": user }
            );
            if (result) {
                const passwordMatch = await comparePassword(password, result.password);
                if (passwordMatch) {
                    const token = generateToken(result.userID);
                    res.status(200).send(
                        {
                            "message": "Login successful",
                            "userID": result.userID,
                            "token": token
                        }
                    );
                } else {
                    res.status(401).send(
                        { "message": "Invalid password" }
                    );
                }
            } else {
                res.status(401).send(
                    { "message": "Invalid user" }
                );
            }
        } else {
            res.status(400).send(
                { "message": "Invalid user" }
            );
        }
    }
});

app.put("/update", async function (req, res) {
    updateSchema.isValid(req.body).then(async function (valid) {
        if (!valid) {
            res.status(400).send({
                "message": "Invalid request"
            });
            return 0;
        }
        const token = req.header.token;
        const userID = req.body.userID
        const password = req.body.password;
        const user = req.body.user;

        if (!token) {
            res.status(401).send(
                { "message": "Invalid token" }
            );
        }
        else if (!verifyToken(token)) {
            res.status(401).send(
                { "message": "Invalid token" }
            );
        }
        else if (!isValidUser(user)) {
            res.status(400).send(
                { "message": "Invalid user" }
            );
        }
        else {
            const hashedPassword = await hashPassword(password);
            const result = await db.collection('login').findOneAndUpdate(
                { "userID": userID }, {
                $set: {
                    "user": user,
                    "password": hashedPassword
                }
            }
            );
            res.send({ "message": "Done, changed user and password" })
        }
    });
});


app.delete("/delete", async function (req, res) {
    if (checkSchema(req, res)) {
        const user = req.body.user;
        const password = req.body.password;
        if (isValidUser(user)) {
            const result = await db.collection('login').findOne(
                { "user": user }
            );
            if (result) {
                const passwordMatch = await comparePassword(password, result.password);
                if (passwordMatch) {
                    await db.collection('login').deleteOne(
                        { "user": user }
                    );
                    res.status(200).send(
                        { "message": "User deleted" }
                    );
                } else {
                    res.status(401).send(
                        { "message": "Invalid password" }
                    );
                }
            } else {
                res.status(401).send(
                    { "message": "Invalid user" }
                );
            }
        } else {
            res.status(400).send(
                { "message": "Invalid user" }
            );
        }
    }
});

app.post("/refresh", async function (req, res) {
    if (checkSchema(req, res)) {
        const user = req.body.user;
        const password = req.body.password;
        if (isValidUser(user)) {
            const result = await db.collection('login').findOne(
                { "user": user }
            );
            if (result) {
                const passwordMatch = await comparePassword(password, result.password);
                if (passwordMatch) {
                    const token = generateToken(result.userID);
                    res.status(200).send({
                        "userID": result.userID,
                        "token": token
                    }
                    );
                } else {
                    res.status(401).send(
                        { "message": "Invalid password" }
                    );
                }
            } else {
                res.status(401).send(
                    { "message": "Invalid user" }
                );
            }
        } else {
            res.status(400).send(
                { "message": "Invalid user" }
            );
        }
    }
});




app.listen(8080, () => { console.log("Running"); })