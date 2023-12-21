// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware')
const router = require('express').Router()
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')


router.post('/register', checkUsernameFree, checkUsernameExists, checkPasswordLength, async (req, res, next) => {
try{
  const { username, password} = req.body
  const hash = bcrypt.hashSync(password, 8)
  const newUser = { username, password: hash}
  const outcome = await Users.add(newUser)
  res.status(200).json({message:`Welcome ${outcome.username}!`})
} catch(err){
  next(err)
}
})

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try{
    const {username, password} = req.body
    const [user] = await Users.findBy({username})
    if(user && bcrypt.compareSync(password, user.password)){
      req.session.user = user
      res.status(200).json({message:`Welcome ${user.username}`})
    }else{
      next({status:401, message:'credentials bad'})
    }
  }catch(err){
    next(err)
  }
})
router.get('/logout', async (req, res, next) => {
  if(req.session.user){
    const {username} = req.session.user
    req.session.destroy((err) => {
      if(err){
        res.json({message:`You may not ever leave ${username}`})

      }else{
        res.json({message:`Goodbye for now, ${username}`})
      }
    })
   
  }else{
    res.json({message:'Have we met before?'})
  }
  next()

})
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router