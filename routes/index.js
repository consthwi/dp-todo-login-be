const express = require("express");
const router = express.Router();
const taskApi = require("./task.api");
const userApi = require("./user.api");

router.use("/tasks", taskApi);
router.use("/user", userApi);
// /tasks경로에 taskApi미들웨어 장착

module.exports = router;
