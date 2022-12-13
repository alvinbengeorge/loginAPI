import express from 'express';
import dotenv from 'dotenv';
import { nanoid } from 'nanoid';
import { comparePassword, hashPassword, isValidUser, generateToken, verifyToken, checkSchema, checkUpdateSchema } from "./utilities/security.js";
import { connectDatabase, find, insertUser, updateUser, removeUser, db } from './utilities/database.js';

const app = express();
app.use(express.json())
dotenv.config()

connectDatabase()

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
        const found = await find(user);
        if (!found) {
            const userID = nanoid(process.env.USERID_LENGTH)
            const hashedPassword = await hashPassword(password);
            await insertUser(user, hashedPassword, userID)
            console.log("User Created ", user)
            res.status(200).send({
                "message": "User created", userID
            });
        } else {
            res.status(400).send(
                { "message": "User Already exists" }
            )
        }
    }
});

app.post("/login", async function (req, res) {
    try {
        checkSchema(req, res)
        const user = req.body.user;
        const password = req.body.password;
        if (isValidUser(user)) {
            const result = await find(user)
            if (result) {
                comparePassword(password, result.password);
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
                    { "message": "User Not Found" }
                );
            }
        } else {
            res.status(400).send(
                { "message": "Invalid user" }
            );
        }
    } catch (error) {
        console.log(error)
        res.status(500).send(
            { "message": error }
        );
    }
});

app.put("/update", async function (req, res) {
    try {
        checkUpdateSchema(req, res)
        const token = req.headers.token;
        const userID = req.body.userID
        const password = req.body.password;
        const user = req.body.user;
        const result = await find(user);

        if (result && result.userID !== userID) {
            res.send({ "message": "Existing User" })
            return 0;
        }

        if (!token || !verifyToken(token)) {
            res.status(401).send(
                { "message": "Invalid token" }
            );
        } else {
            const hashedPassword = await hashPassword(password);
            await updateUser(user, hashedPassword, userID);
            res.send({ "message": "Done, changed user and password" })
        }
    } catch (error) {
        console.log(error)
        res.status(500).send(
            { "message": error }
        );
    }
});


app.delete("/delete", async function (req, res) {
    try {
        checkSchema(req, res)
        const user = req.body.user;
        const password = req.body.password;
        const token = req.headers.token;
        if (isValidUser(user)) {
            const result = await find(user)
            if (result) {
                const passwordMatch = await comparePassword(password, result.password);
                if (passwordMatch && verifyToken(token)) {
                    await removeUser(user);
                    res.status(200).send(
                        { "message": "User deleted" }
                    );
                } else {
                    res.status(401).send(
                        { "message": "Token Error" }
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
    } catch (error) {
        res.status(500).send({
            "message": error
        })
    }
});

app.post("/refresh", async function (req, res) {
    try {
        checkSchema(req, res);
        const user = req.body.user;
        const password = req.body.password;
        if (isValidUser(user)) {
            const result = await find(user);
            if (result) {
                comparePassword(password, result.password)
                const token = generateToken(result.userID);
                res.status(200).send({                        
                        "token": token
                });
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
    } catch (error) {
        res.status(500).send(
            { "message": error }
        );
    }
});


app.listen(process.env.PORT, () => { console.log("Running"); })