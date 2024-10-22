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
    const user = await User.findOne({ email: email });

    // 사용자가 없을 경우 오류 처리 추가
    if (!user) {
      throw new Error("등록되지 않은 이메일입니다.");
    }

    const isMatch = bcrypt.compareSync(password, user.password);
    if (isMatch) {
      const token = user.generateToken();
      return res.status(200).json({ status: "ok", user, token });
    } else {
      throw new Error("아이디 또는 비밀번호가 일치하지 않습니다.");
    }
  } catch (err) {
    res.status(400).json({ status: "fail", message: err.message });
  }
};

module.exports = userController;
