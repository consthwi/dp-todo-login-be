const User = require("../model/User");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const userController = {};

userController.createUser = async (req, res) => {
  const { name, email, password } = req.body;
  // => post하는 데이터는 {name, email, password}이다.
  try {
    // 1. 유저확인 후
    const user = await User.findOne({ email: email });
    if (user) {
      throw new Error("이미 가입이 완료된 이메일주소입니다");
    }
    // 2. 패스워드 암호화 (sync생성법이 더 명료)
    const salt = bcrypt.genSaltSync(saltRounds);
    const hash = bcrypt.hashSync(password, salt);
    // console.log(hash);
    const newUser = new User({ email: email, name: name, password: hash });
    await newUser.save();
    res.status(200).json({ status: "ok" });
  } catch (error) {
    // json내의 객체가 error객체 그 자체이다.
    res.status(400).json({ status: "fail", message: error.message });
  }
};

// 2-1) 라우터 설정
// 2-2) 이메일 패스워드 정보 읽어오기
// 2-3) 이메일을 가지고 유저정보 가져오기
// 2-4) 이 유저의 DB에 있는 패스워드와
//      프론트엔드가 보낸 패스워드가 같은지 비교
// 2-5) 맞다면? 토큰 발행
// 2-6) 아니다면? 에러메세지
// 2-7) 응답으로 유저정보 + 토큰 send

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
      // fe pw와 hash를 비교
    }
  } catch (err) {
    res.status(400).json({ status: "fail", message: err.message });
  }
};

module.exports = userController;
