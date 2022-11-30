import express from 'express';
import dotenv from 'dotenv';
import { nanoid } from 'nanoid';
import { updateSchema } from './utilities/schemas.js';
import { comparePassword, hashPassword, isValidUser, generateToken, verifyToken, checkSchema } from "./utilities/security.js";
import { connectDatabase, findByUser, findByUserID, insertUser, updateUser, removeUser, db } from './utilities/database.js';

const app = express();
app.use(express.json())
dotenv.config()

connectDatabase()

const USERID_LENGTH = 10; // change this as per your need

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
        const found = await findByUser(user);
        if (isValidUser(user) && !found) {
            const userID = nanoid(USERID_LENGTH)
            const hashedPassword = await hashPassword(password);
            await insertUser(user, hashedPassword, userID)
            console.log("User Created ", user)
            res.status(200).send(
                {
                    "message": "User created",
                    "userID": userID
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
            const result = await findByUser(user)
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
        const token = req.headers.token;
        const userID = req.body.userID
        const password = req.body.password;
        const user = req.body.user;
        const result = await findByUser(user);

        if (result) {
            res.send({ "message": "Existing User" })
            return 0;
        }

        if (!token || !verifyToken(token)) {
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
            await updateUser(user, hashedPassword, userID);
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
                    await removeUser(user);
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
            const result = await findByUser(user);
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


app.listen(process.env.PORT, () => { console.log("Running"); })