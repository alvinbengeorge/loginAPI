import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { schema, updateSchema } from './schemas.js';

const saltRounds = process.env.saltRounds;


dotenv.config()

function hashPassword(password) {
    return bcrypt.hash(password, saltRounds);
}

function comparePassword(password, hash) {
    return bcrypt.compare(password, hash);
}

function generateToken(userID) {
    const data = {
        "userID": userID,
        "timestamp": Date.now()
    }
    console.log(process.env.expiresIn)
    return jwt.sign(data, process.env.SECRET, { expiresIn: process.env.expire });
}

async function checkSchema(req, res) {
    const valid = schema.isValid(req.body)
    if (valid) {
        return true
    } else {
        throw new Error("Invalid schema")
    }
}

async function checkUpdateSchema(req, res) {
    const valid = updateSchema.isValid(req.body)
    if (valid) {
        return true
    } else {
        throw new Error("Invalid schema")
    }
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