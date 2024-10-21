const User = require("../model/User");
const bcrypt = require("bcryptjs");
const saltRounds = 10;

const userController = {};

userController.createUser = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const user = await User.findOne({ email: email });
    if (user) {
      throw new Error("이미 가입이 완료된 이메일주소입니다");
    }
    const salt = bcrypt.genSaltSync(saltRounds);
    const hash = bcrypt.hashSync(password, salt);
    const newUser = new User({ email: email, name: name, password: hash });
    await newUser.save();
    res.status(200).json({ status: "ok" });
  } catch (error) {
    res.status(400).json({ status: "fail", message: error.message });
  }
};

userController.loginWithEmail = async (req, res) => {
  try {
    const { email, password } = req.body;
    // => get()은 req.body사용 불가
    const joinedUser = await User.findOne({ email: email });
    if (joinedUser) {
      const isMatch = bcrypt.compareSync(password, joinedUser.password);
      if (isMatch) {
        const token = joinedUser.generateToken();
        return res.status(200).json({ status: "ok", joinedUser, token });
      } else {
        throw new Error("아이디 또는 비밀번호가 일치하지 않습니다.");
      }
    }
  } catch (err) {
    res.status(400).json({ status: "fail", message: err.message });
  }
};

module.exports = userController;
