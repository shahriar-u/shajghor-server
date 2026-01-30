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

    // সব সার্ভিস দেখা (Public + Admin Filtering)
    app.get("/services", async (req, res) => {
      const email = req.query.email;
      let query = {};
      if (email) {
        const user = await usersCollection.findOne({ email: email });
        query = user?.role === "admin" ? {} : { status: "active" };
      } else {
        query = { status: "active" };
      }
      const result = await serviceCollection.find(query).toArray();
      res.send(result);
    });

    // সিঙ্গেল সার্ভিস ডিটেইলস
    app.get("/service/:id", async (req, res) => {
      const id = req.params.id;
      const result = await serviceCollection.findOne({ _id: new ObjectId(id) });
      if (!result) return res.status(404).send({ message: "Not Found" });
      res.send(result);
    });

   

    // নতুন সার্ভিস যোগ করা (Admin/Decorator)
    app.post("/services", verifyJWT, async (req, res) => {
      const newService = req.body;
      const email = req.decoded.email;
      const user = await usersCollection.findOne({ email: email });
      const currentRole = user?.role?.toLowerCase();

      if (currentRole !== "decorator" && currentRole !== "admin") {
        return res.status(403).send({ error: true, message: "Forbidden" });
      }

      const finalService = {
        ...newService,
        price: parseFloat(newService.price),
        decoratorCommission: parseFloat(newService.decoratorCommission),
        totalBookings: 0,
        status: "active",
        addedBy: email,
        createdAt: new Date(),
      };
      const result = await serviceCollection.insertOne(finalService);
      res.send(result);
    });

    

    // সার্ভিস আপডেট (Admin Only)
    app.put("/services/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const updatedService = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          ...updatedService,
          price: parseFloat(updatedService.price),
          decoratorCommission: parseFloat(updatedService.decoratorCommission),
        },
      };
      const result = await serviceCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    /** --- 4. BOOKING & SCHEDULE MANAGEMENT --- **/

    // নতুন বুকিং তৈরি
    app.post("/bookings", async (req, res) => {
      try {
        const result = await bookingCollection.insertOne(req.body);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Booking Error" });
      }
    });

    // ইউজারের নিজস্ব বুকিং লিস্ট (Pagination & Sort)
    app.get("/bookings", verifyJWT, async (req, res) => {
      const email = req.query.email;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden Access" });

      const page = parseInt(req.query.page) || 1;
      const size = parseInt(req.query.size) || 4;
      const sortField = req.query.sort || "date";
      const query = { userEmail: email };

      let sortOptions = {};
      if (sortField === "date") sortOptions = { date: -1 };
      else if (sortField === "price") sortOptions = { price: 1 };
      else if (sortField === "paymentStatus")
        sortOptions = { paymentStatus: 1 };

      const totalCount = await bookingCollection.countDocuments(query);
      const result = await bookingCollection
        .find(query)
        .sort(sortOptions)
        .skip((page - 1) * size)
        .limit(size)
        .toArray();
      res.send({ result, totalCount });
    });

    // বুকিং ডিলিট (Cancel)
    app.delete("/bookings/:id", async (req, res) => {
      const result = await bookingCollection.deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    });

    // অ্যাডমিন সব বুকিং দেখবে
    app.get("/admin/all-bookings", verifyJWT, verifyAdmin, async (req, res) => {
      const result = await bookingCollection.find().toArray();
      res.send(result);
    });

   // ডেকোরেটর অ্যাসাইন করা (Admin Only)
    app.patch(
      "/admin/assign-decorator/:id",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const result = await bookingCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: req.body }
        );
        res.send(result);
      }
    );

    // ডেকোরেটর লিস্ট দেখা (Admin Only)
    app.get(
      "/admin/available-decorators",
      verifyJWT,
      verifyAdmin,
      async (req, res) => {
        const result = await usersCollection
          .find({ role: "decorator" })
          .toArray();
        res.send(result);
      }
    );

    // ডেকোরেটরের নিজের অ্যাসাইন করা কাজ
    app.get("/my-assigned-services/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden" });
      const result = await bookingCollection
        .find({ decoratorEmail: email, status: "assigned" })
        .toArray();
      res.send(result);
    });

    // ডেকোরেটর স্ট্যাটাস আপডেট (Completed/In-progress)
    app.patch("/assigned-services/status/:id", verifyJWT, async (req, res) => {
      const result = await bookingCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { decoratorStatus: req.body.status } }
      );
      res.send(result);
    });

    // ডেকোরেটরের আজকের শিডিউল
    app.get("/today-schedule/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden" });
      const today = new Date().toISOString().split("T")[0];
      const result = await bookingCollection
        .find({ decoratorEmail: email, date: today, status: "assigned" })
        .toArray();
      res.send(result);
    });

    /** --- 5. PAYMENT & STRIPE APIs --- **/

    // স্ট্রাইপ পেমেন্ট সেশন তৈরি
    app.post("/create-checkout-session", async (req, res) => {
      try {
        const paymentInfo = req.body;
        const amount = parseInt(paymentInfo.price) * 100;
        console.log(
          `${process.env.SITE_URL}/dashboard/payment-success/}`
        );
        
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "USD",
                unit_amount: amount,
                product_data: { name: paymentInfo.name },
              },
              quantity: 1,
            },
          ],
          mode: "payment",
          customer_email: paymentInfo.user_email,
          metadata: { serviceId: paymentInfo.serviceID },
          success_url: `${process.env.SITE_URL}/dashboard/payment-success/${paymentInfo.serviceID}`,
          cancel_url: `${process.env.SITE_URL}/dashboard/my-bookings`,
        });
        res.send({ url: session.url });
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    });

    // পেমেন্ট সাকসেস হলে স্ট্যাটাস 'paid' করা
    app.patch("/bookings/payment-success/:id", async (req, res) => {
      const result = await bookingCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { paymentStatus: "paid" } }
      );
      res.send(result);
    });

    // ইউজারের পেমেন্ট হিস্ট্রি
    app.get("/payments/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden" });
      const result = await bookingCollection
        .find({ userEmail: email, paymentStatus: "paid" })
        .toArray();
      res.send(result);
    });

    /** --- 6. STATS & ANALYTICS APIs --- **/

    // ডেকোরেটর আর্নিং সামারি
    app.get("/decorator-earnings/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.decoded.email)
        return res.status(403).send({ message: "Forbidden" });
      const query = {
        decoratorEmail: email,
        decoratorStatus: "Completed",
        paymentStatus: "paid",
      };
      const tasks = await bookingCollection.find(query).toArray();
      const totalEarnings = tasks.reduce(
        (sum, task) => sum + parseFloat(task.price || 0),
        0
      );
      res.send({ totalEarnings, taskCount: tasks.length, history: tasks });
    });

    // অ্যাডমিন অ্যানালিটিক্স (Revenue & Demand)
    app.get("/admin-stats", verifyJWT, verifyAdmin, async (req, res) => {
      const bookings = await bookingCollection
        .find({ paymentStatus: "paid" })
        .toArray();
      const totalRevenue = bookings.reduce(
        (sum, item) => sum + parseFloat(item.price || 0),
        0
      );
      const demandData = {};
      bookings.forEach((item) => {
        const name = item.serviceTitle || item.serviceName;
        demandData[name] = (demandData[name] || 0) + 1;
      });
      const chartData = Object.keys(demandData)
        .map((name) => ({ name, count: demandData[name] }))
        .sort((a, b) => b.count - a.count);
      res.send({ totalRevenue, totalBookings: bookings.length, chartData });
    });



    ///////////// old/////////////
    // ২. সকল ইউজার দেখা (অ্যাডমিনের জন্য)
    app.get("/users", verifyJWT, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    // ৩. ইউজারের রোল চেক করা (Admin কি না)
    app.get("/users/admin/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (req.decoded.email !== email) {
        res.send({ admin: false });
      }
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const result = { admin: user?.role === "admin" };
      res.send(result);
    });

    // ৪. ইউজারের রোল চেক করার রুট (ব্যবহারকারী admin, decorator নাকি user তা জানাবে)
    app.get("/users/role/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;

      // টোকেনের ইমেইল আর রিকোয়েস্টের ইমেইল মিলছে কিনা চেক (Security)
      if (req.decoded.email !== email) {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden Access" });
      }

      const query = { email: email };
      const user = await usersCollection.findOne(query);

      // ডাটাবেজে ইউজার থাকলে তার রোল পাঠাবে, না থাকলে ডিফল্ট 'user'
      res.send({ role: user?.role || "user" });
    });

    // ইউজার রোল আপডেট করার এন্ডপয়েন্ট (Admin Only)
    app.patch("/users/role/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const { role } = req.body; // ফ্রন্টএন্ড থেকে 'decorator' বা 'admin' আসবে
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: { role: role.toLowerCase() }, // সব সময় ছোট হাতের অক্ষরে সেভ হবে
      };
      const result = await usersCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // নির্দিষ্ট ডেকোরেটরের নিজের সার্ভিসগুলো দেখার রুট
    app.get("/my-services/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;

      // সিকিউরিটি চেক: যে রিকোয়েস্ট করছে সে কি তার নিজের ডাটাই চাচ্ছে?
      if (req.decoded.email !== email) {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden access" });
      }

      const query = { decoratorEmail: email };
      const result = await serviceCollection.find(query).toArray();
      res.send(result);
    });

    // ১. সার্ভিস ডিলিট করার এপিআই
    app.delete("/services/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await serviceCollection.deleteOne(query);
      res.send(result);
    });

   

    
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
 