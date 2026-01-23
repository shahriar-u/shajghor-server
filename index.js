const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const cors = require("cors");
var jwt = require("jsonwebtoken");
require("dotenv").config();
const port = process.env.PORT || 5000;

const stripe = require("stripe")(process.env.STRIPE_SECRET);

app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;

  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "Unauthorized Access first check" });
  }
  const token = authorization.split(" ")[1];

  jwt.verify(token, process.env.USER_VERIFY_TOKEN, (error, decoded) => {
    if (error) {
      console.log("JWT Error:", error.message);
      return res
        .status(401)
        .send({ error: true, message: "Unauthorized Access second check" });
    }
    req.decoded = decoded;

    next();
  });
};


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.1ikjvvw.mongodb.net/?appName=Cluster0`;


const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

    const db = client.db("shajghorDB");
    const usersCollection = db.collection("users");

    const serviceCollection = db.collection("services");
    const bookingCollection = db.collection("bookings");

    // jwt token

    
