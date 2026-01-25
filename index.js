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

    // নতুন ইউজার তৈরি (Signup)
    app.post("/create_user", async (req, res) => {
      const user = req.body;
      const query = { email: user.email };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser)
        return res.send({ message: "User already exists", insertedId: null });

      const newUser = {
        name: user.name,
        email: user.email,
        image: user.image,
        role: "user",
        status: "active",
        createdAt: new Date(),
        totalEarnings: 0,
        currentBalance: 0,
        wishlist: [],
        orders: [],
      };
      const result = await usersCollection.insertOne(newUser);
      res.send(result);
    });

    
    app.get("/users/profile/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden Access" });
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      res.send(user);
    });

    // প্রোফাইল আপডেট (Patch)
    app.patch("/users/update-profile/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      const updatedData = req.body;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden Access" });

      const filter = { email: email };
      const updateFields = {};
      if (updatedData.name?.trim()) updateFields.name = updatedData.name;
      if (updatedData.phone?.trim()) updateFields.phone = updatedData.phone;
      if (updatedData.address?.trim())
        updateFields.address = updatedData.address;

      if (Object.keys(updateFields).length === 0)
        return res.status(400).send({ message: "No valid data provided" });
      const result = await usersCollection.updateOne(filter, {
        $set: updateFields,
      });
      res.send(result);
    });

    // ইউজার স্ট্যাটাস পরিবর্তন (Admin Only)
    app.patch("/users/status/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;
      const filter = { _id: new ObjectId(id) };
      const result = await usersCollection.updateOne(filter, {
        $set: { status: status },
      });
      res.send(result);
    });

    /** --- 3. SERVICE MANAGEMENT --- **/

    