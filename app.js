const mongoose = require("mongoose");
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const indexRouter = require("./routes/index");
require("dotenv").config();
const MONGODB_URI_PROD = process.env.MONGODB_URI_PROD;
console.log("mongouri", MONGODB_URI_PROD);

const app = express();
app.use(bodyParser.json());
app.use(cors());

app.use("/api", indexRouter);

const mongoURI = MONGODB_URI_PROD;
mongoose
  .connect(mongoURI, { useNewUrlParser: true })
  .then(() => {
    console.log("mongoose connected");
  })
  .catch((err) => {
    console.log("db connection failed", err);
  });

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
