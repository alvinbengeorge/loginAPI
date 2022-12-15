import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { schema, updateSchema } from './schemas.js';

const saltRounds = 10;


dotenv.config()

function hashPassword(password) {
    return bcrypt.hash(password, saltRounds);
}

async function comparePassword(password, hash) {
    const result = await bcrypt.compare(password, hash);
    if (result) {
        return true
    } else {
        throw new Error("Invalid Password")
    }

}

function generateToken(userID) {
    const data = {
        "userID": userID,
        "timestamp": Date.now()
    }
    return jwt.sign(data, process.env.SECRET, { expiresIn: process.env.expire });
}

async function checkSchema(req, res) {
    const valid = await schema.isValid(req.body)
    if (valid) {
        return true
    } else {
        throw new Error("Invalid schema")
    }
}

async function checkUpdateSchema(req, res) {
    const valid = updateSchema.isValid(req.body);
    if (valid) {
        return true
    } else {
        throw new Error("Invalid schema")
    }
}

function verifyToken(token) {
    return jwt.verify(token, process.env.SECRET);
}


export {
    hashPassword,
    comparePassword,
    generateToken,
    verifyToken,
    checkSchema,
    checkUpdateSchema
};