const AuthService = require('../middleware/auth-service')

function requireAuth(req, res, next) {
   
    const authToken = req.get('Authorization') || ''
    let basicToken

    if (!authToken.toLowerCase().startsWith('basic ')) {
     return res.status(401).json({ error: 'Missing basic token' })
   }
   //parsing the base64 basic token value out of the header and return error username
   //or password not present.
  else {
       basicToken = authToken.slice('basic '.length, authToken.length)
       }
    
       const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(basicToken) 
       
    
     if (!tokenUserName || !tokenPassword) {
         return res.status(401).json({ error: 'Unauthorized request' })
       }
       //query the database for user to match the passed username
       AuthService.getUserWithUserName(
        req.app.get('db'),
        tokenUserName
       )
        .then(user => {
            if (!user || user.password !== tokenPassword) {
              return res.status(401).json({ error: 'Unauthorized request' })
            }
       
            next()
          })
          .catch(next)
  }
  
  module.exports = {
    requireAuth,
  }