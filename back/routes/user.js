const express = require('express');
const oracledb = require('oracledb');
const bcrypt = require('bcrypt');
const db = require("../db");
const router = express.Router();

const saltRounds = 10;

router.post('/login', async (req, res) => {
  const { userId, pwd } = req.body;
  console.log(req.body);
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
    if(result.rows.length > 0){
      let match = await bcrypt.compare(pwd, result.rows[0].PWD);
      if(match){
        isLogin = true;
        message = "로그인 성공!"; 
      } 
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

module.exports = router;