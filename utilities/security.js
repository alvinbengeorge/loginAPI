import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { schema, updateSchema } from './schemas.js';

const saltRounds = 10;


dotenv.config()

function hashPassword(password) {
    return bcrypt.hash(password, saltRounds);
}

function comparePassword(password, hash) {
    bcrypt.compare(password, hash).then(function (result) {
        if (result) {
            return true
        } else {
            throw new Error("Invalid password")
        }
    });
}

function generateToken(userID) {
    const data = {
        "userID": userID,
        "timestamp": Date.now()
    }
    return jwt.sign(data, process.env.SECRET, { expiresIn: process.env.expire });
}

function checkSchema(req, res) {
    schema.isValid(req.body).then(function (valid) {
        if (valid) {
            console.log(valid)
            return true
        } else {
            throw new Error("Invalid schema")
        }
    });
}

function checkUpdateSchema(req, res) {
    updateSchema.isValid(req.body).then(function (valid) {
        if (valid) {
            return true
        } else {
            throw new Error("Invalid schema")
        }
    });
}

function verifyToken(token) {
    return jwt.verify(token, process.env.SECRET);
}

function validateEmail(email) {
    const re = /\S+@\S+\.\S+/;
    return re.test(email);
}


function validatePhone(phone) {
    const re = /^\d{10}$/;
    return re.test(phone);
}

function isValidUser(user) {
    return validateEmail(user) || validatePhone(user);
}

export {
    hashPassword,
    comparePassword,
    isValidUser,
    generateToken,
    verifyToken,
    checkSchema,
    checkUpdateSchema
};