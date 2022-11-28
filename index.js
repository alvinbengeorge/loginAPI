const express = require("express");
const mongodb = require("mongodb");
const dotenv = require("dotenv");
const yup = require("yup");


dotenv.config()
const app = express();
app.use(express.json());
const mongoDB = `mongodb+srv://${process.env.login}:${process.env.pass}@cluster0.qxkfxbf.mongodb.net/?retryWrites=true&w=majority`;

async function connect(){
    const mongoClient = new mongodb.MongoClient(mongoDB, { useNewUrlParser: true, useUnifiedTopology: true });
    await mongoClient.connect();
}
connect()


app.get("/health", async function(req, res) {
    res.send(
        {"status": "Online", "uptime": process.uptime()}
    );
});

app.listen(8080, () => {console.log("Running");})