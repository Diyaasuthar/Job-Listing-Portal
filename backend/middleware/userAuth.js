const jwt = require('jsonwebtoken');

const userAuth = async (req, res, next) => {
    const token  = req.headers['authorization']?.split(" ")[1];

    if(!token){
        return res.json({ success: false, message: "Unauthorized. Login Again"});
    }

    try {
        
      const tokenDecode =  jwt.verify(token, process.env.JWT_SECRET);
      if(tokenDecode.id){
        if(!req.body) req.body = {};
        req.body.userId = tokenDecode.id;
      }else{
        return res.json({ success: false, message: "Unauthorized. Login Again"});
      }

      next();

       

    } catch (error) {
        res.json({ success: false, messasge: error.message });
    }
}

module.exports = userAuth;