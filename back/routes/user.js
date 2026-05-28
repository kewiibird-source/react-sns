const express = require('express');
const oracledb = require('oracledb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const jwtAuthentication = require('../auth')
const db = require("../db");

const router = express.Router();
require("dotenv").config();
const JWT_KEY = process.env.jwt_key; // .env사용
// 해시 함수 실행 위해 사용할 키로 아주 긴 랜덤한 문자를 사용하길 권장하며, 노출되면 안됨.
// .env로 관리해야 한다

const saltRounds = 10;

// 회원가입
router.post('/join', async (req, res) => {
  const { userId, pwd, userName } = req.body;
  const hashPwd = await bcrypt.hash(pwd, saltRounds); // 암호화된 pwd
  let connection;
  try {
    connection = await db.getConnection();
    const result = await connection.execute(
      `
        INSERT INTO TBL_USER(USERID, PWD, USERNAME) VALUES(:userId, :hashPwd, :userName)
      `,
      [userId, hashPwd, userName],
      {autoCommit : true}
    );
    let isLogin = false;
    let message = "회원가입 실패!";
    if(result.rowsAffected > 0){
      isLogin = true;
      message = "회원가입 성공!";
    }

    res.json({
        result : isLogin,
        message : message
        // list : result.rows
    });
    
  } catch (error) {
    console.error('Error executing query', error);
    res.status(500).send('Error executing query');
  } finally {
    await connection.close();
  }
});

// 로그인
router.post('/login', async (req, res) => {
  const { userId, pwd } = req.body;
  let connection;
  try {
    connection = await db.getConnection();
    const result = await connection.execute(
      `
        SELECT * FROM TBL_USER WHERE USERID = :userId
      `,
      [userId],
      {outFormat: oracledb.OUT_FORMAT_OBJECT}
    );
   
    let isLogin = false;
    let message = "로그인 실패!";
    let token = null;
    if(result.rows.length > 0){
      let match = await bcrypt.compare(pwd, result.rows[0].PWD);
      if(match){
        isLogin = true;
        message = "로그인 성공!"; 
        let payload = {
          userId : result.rows[0].USERID,
          userName : result.rows[0].USERNAME,
          role : result.rows[0].ROLE
        }

        token = jwt.sign(payload, JWT_KEY, {expiresIn : '1h'});
        console.log(JWT_KEY);
        console.log(token);
      } 
    }
    res.json({
        result : isLogin,
        message : message,
        token : token
        // list : result.rows
    });
    
  } catch (error) {
    console.error('Error executing query', error);
    res.status(500).send('Error executing query');
  } finally {
    await connection.close();
  }
});

// 마이페이지 유저정보 가져오기
router.get('/:userId', jwtAuthentication, async (req, res) => {
  const { userId } = req.params;
  let connection;
  try {
    connection = await db.getConnection();
    const result = await connection.execute(
      `
        SELECT U.*, CNT
        FROM TBL_USER U
        LEFT JOIN (
            SELECT COUNT(*) AS CNT, USERID
            FROM TBL_FEED
            GROUP BY USERID
        ) T ON U.USERID = T.USERID
        WHERE U.USERID = :userId
      `,
      [userId],
      {outFormat: oracledb.OUT_FORMAT_OBJECT}
    );
    
    res.json({
        result : "success",
        info : result.rows[0]
    });
    
  } catch (error) {
    console.error('Error executing query', error);
    res.status(500).send('Error executing query');
  } finally {
    await connection.close();
  }
});


module.exports = router;