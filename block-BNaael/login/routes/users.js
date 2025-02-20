var express = require('express');
var router = express.Router();
var User = require('../models/user')

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.json({message: 'Users Information'});
});
//Regstration handler.
router.get('/register',async (req, res, next)=>{
  try {
    var user = await User.create(req.body);
    console.log(user);
    res.status(200).json({user});
  } catch (error) {
    next(error);
  }
});
//Login handler.
router.post("/login",async (req, res, next)=>{
  var{ email , password } = req.body;
  if(!email || !password) {
    return res.status(400).json({error : "Email/password required"});
  }
  try {
    var user = await User.findone({email});
    if(!user){
      return res.status(400).json({error : "Email not registered"})
    }
    var result = await User.verifyPassword(password);
    console.log(result);
    if (!result) {
      return res.status(400).json({error : "Invalid password"});
    }
    //generate token
  }
  catch (error) {
    next(error);
  }
})

module.exports = router;
