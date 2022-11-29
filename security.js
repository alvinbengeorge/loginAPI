import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import yup from 'yup';

const saltRounds = 10;
const schema = yup.object().shape({
    user: yup.string().trim().required(),
    password: yup.string().trim().required()
});
const updateSchema = yup.object().shape({
    username: yup.string().trim().required(),
    password: yup.string().trim().required(),
    userID: yup.string().trim().required()
});

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
    return jwt.sign(data, process.env.SECRET, {expiresIn: '24h'});
}

async function checkSchema(req, res) {
    schema.isValid(req.body).then(function(valid) {
        if (valid) {
            return true;
        } else {
            res.send(
                {
                    "message": "Invalid request body",
                    "schema": schema.describe()
                }
            )
            return false;
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
    updateSchema
};