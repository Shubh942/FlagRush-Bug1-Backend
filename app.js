const mongoose = require("mongoose");
const express = require("express");
const cors = require("cors");

// const AppError = require('./utils/appError');
const globalErrorController = require("./controllers/errorController");
const userRouter = require("./routes/userRoutes");

const app = express();

//Middle ware for cors permission
app.use(cors());

//Converting req in json format
app.use(express.json());

app.use(express.urlencoded({ extended: true, limit: "10kb" }));

//User Routes
app.use("/api/v1/users", userRouter);

//Route of global error handler
app.use(globalErrorController);

module.exports = app;
