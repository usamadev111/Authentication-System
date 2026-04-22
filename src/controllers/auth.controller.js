import userModel from "../models/user.model.js"
import crypto from "crypto"
import jwt from "jsonwebtoken"
import config from "../config/config.js"

export async function register(req, res) {
    
    const {username, email, password} = req.body

    const userAlreadyExists = await userModel.findOne({
        $or: [
            {username},
            {email}
        ]
    })

    if(userAlreadyExists){
        res.status(409).json({
            message: "User Already Exists"
        })
    }

    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex")
    

    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    })

    const token = jwt.sign({
        id: user._id,
    }, config.JWT_SECRET,
    {
        expiresIn: "1d"
    })

    res.status(201).json({
        message: "User Registered Successfully",
        user: {
            username: user.username,
            email: user.email,
        },
        token
    })

}

export async function getToken(req, res) {

    const token = req.headers.authorization?.split(" ")[ 1 ]

    if(!token){
        return res.status(401).json({
            message: "Unauthorized User or the Token is Not Found"
        })
    }

    const decoded = await jwt.verify(token, config.JWT_SECRET)

    console.log(decoded);

    const user = await userModel.findById(decoded.id)

    res.status(200).json({
        message: "User Fetched Successfully",
        user: {
            username: user.username,
            email: user.email
        }
    })
    

} 