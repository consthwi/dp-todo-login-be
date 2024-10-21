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

// app에 항상 router세팅... 그래서 exports하는거
app.use("/api", indexRouter);

// 백엔드는 env읽기 위해 npm 설치해야한다.
const mongoURI = MONGODB_URI_PROD;
mongoose
  .connect(mongoURI, { useNewUrlParser: true })
  .then(() => {
    console.log("mongoose connected");
  })
  .catch((err) => {
    console.log("db connection failed", err);
  });

app.listen(5000, () => {
  console.log("server on 5000");
});

// 1. 회원가입
// 유저가 이메일, 패스워드, 유저이름
// 받은 정보를 저장함 ( => 데이터베이스 모델 필요)
// 패스워드를 암호화 시켜서 저장

// 1-1) 라우터
// 1-2). 모델
// 1-3). 데이터를 저장 (이미 가입된 유저 유무 판별, 패스워드 암호화)
// 1-4). 응답을 보낸다

// 2. 로그인
// 이메일 패스워드를 입력해서 보냄
// 데이터베이스에 해당 이메일과 패스워드를 가진 유저가 있는지 확인
// 없다면? 로그인 실패
// 있다면? 유저정보 + 토큰
// 프론트엔드에서는 이 정보를 저장

// 2-1) 라우터 설정
// 2-2) 이메일 패스워드 정보 읽어오기
// 2-3) 이메일을 가지고 유저정보 가져오기
// 2-4) 이 유저의 DB에 있는 패스워드와
//      프론트엔드가 보낸 패스워드가 같은지 비교
// 2-5) 맞다면? 토큰 발행
// 2-6) 아니다면? 에러메세지
// 2-7) 응답으로 유저정보 + 토큰 send
