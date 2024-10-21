const express = require("express");
const userController = require("../controller/user.controller");
const router = express.Router();

// 1. 회원가입 endpoint
router.post("/", userController.createUser);
router.post("/login", userController.loginWithEmail);
// => 회원정보(email, password)를 *보내서 매칭해서 가져오기 위함.

module.exports = router;
