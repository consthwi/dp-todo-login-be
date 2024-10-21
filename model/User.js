const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const jwt = require("jsonwebtoken");
require("dotenv").config();
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

const userSchema = Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

// *json으로 변환할때 항상 호출되는 함수 정의 (for데이터 가공)
userSchema.methods.toJSON = function () {
  const obj = this._doc;
  delete obj.password;
  delete obj.createdAt;
  delete obj.updatedAt;
  delete obj.__v;
  return obj;
};
// 화살표함수로 사용하면 this가 변경됨
// userSchema.methods.toJSON = () => {
//   return this;
// };

//토큰도 관련있는 모델에 메서드를 정의하는 것이 좋다.
userSchema.methods.generateToken = () => {
  const token = jwt.sign({ _id: this._id }, JWT_SECRET_KEY, {
    expiresIn: "1d",
  });
  return token;
};

const User = mongoose.model("User", userSchema);

module.exports = User;
