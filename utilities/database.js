import mongodb from 'mongodb';

const client = new mongodb.MongoClient(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true });

async function connectDatabase() {
    await client.connect();
    console.log("Connected to MongoDB");
    return client;

}
const db = client.db('loginAPI');

async function find(input) {
    return await db.collection('login').findOne(input);
}

async function findByUser(user) {
    return await find({ "user": user }, db)
}

async function findByUserID(userID) {
    return await find({ "userID": userID });
}

async function insert(input) {
    return await db.collection('login').insertOne(input);
}

async function insertUser(user, password, userID) {
    return await insert({ "user": user, "password": password, "userID": userID }, db);
}

async function updateUser(user, password, userID) {
    return await db.collection('login').findOneAndUpdate({ "userID": userID, $set: { "user": user, "password": password } });
}

async function remove(input) {
    return await db.collection('login').deleteOne(input);
}

async function removeUser(user) {
    return await remove({ "user": user }, db);
}


export {
    connectDatabase,
    find,
    findByUser,
    findByUserID,
    insert,
    insertUser,
    updateUser,
    remove,
    removeUser,
    db
};