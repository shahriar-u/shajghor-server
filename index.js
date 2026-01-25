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

    app.post("/jwt-token", async (req, res) => {
      const user = req.body;

      // ডাটাবেজে চেক করা ইউজার এক্টিভ কি না
      const dbUser = await usersCollection.findOne({ email: user.email });

      if (dbUser && dbUser.status === "disabled") {
        return res.status(403).send({
          error: true,
          message: "Your account is disabled. Contact Admin.",
        });
      }

      const token = jwt.sign(user, process.env.USER_VERIFY_TOKEN, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    // মিডলওয়্যার: অ্যাডমিন ভেরিফিকেশন
    
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email; 
      const query = { email: email };
      const user = await usersCollection.findOne(query);

      if (user?.role !== "admin") {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden: Admin access only" });
      }
      next();
    };



    /** --- 1. AUTHENTICATION & ROLE CHECK APIs --- **/

    
    app.get("/users/admin/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden" });
      const user = await usersCollection.findOne({ email });
      res.send({ admin: user?.role === "admin" });
    });

    // টোকেন যাচাই করে ইউজার ডেকোরেটর কি না
    app.get("/users/decorator/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden" });
      const user = await usersCollection.findOne({ email });
      res.send({ decorator: user?.role === "decorator" });
    });

    // ইউজারের কারেন্ট স্ট্যাটাস চেক (Active/Disabled)
    app.get("/user/status/:email", async (req, res) => {
      try {
        const email = req.params.email;
        const user = await usersCollection.findOne({ email: email });
        if (!user) return res.send({ status: "active" });
        res.send({ status: user.status });
      } catch (error) {
        res.status(500).send({ message: "Error checking status" });
      }
    });



    /** --- 2. USER & PROFILE MANAGEMENT --- **/

    