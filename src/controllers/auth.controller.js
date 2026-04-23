import userModel from "../models/user.model.js"
import crypto from "crypto"
import jwt from "jsonwebtoken"
import config from "../config/config.js"
import sessionModel from "../models/session.model.js"

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

    const refreshToken = jwt.sign({
        id: user._id,
    }, config.JWT_SECRET,
    {
        expiresIn: "7d"
    })

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session = await sessionModel.create({
        user: user._id,
        refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers["user-agent"]
    })

    const accessToken = jwt.sign({
        id: user._id,
        sessionId: session._id
    }, config.JWT_SECRET,
    {
        expiresIn: "15m"
    })
    

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    res.status(201).json({
        message: "User Registered Successfully",
        user: {
            username: user.username,
            email: user.email,
        },
        accessToken
    })

}

export async function getToken(req, res) {

    const token = req.headers.authorization?.split(" ")[ 1 ]

    // console.log(token);
    

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

export async function refreshToken(req, res) {
    
    const refreshToken = req.cookies.refreshToken

    if(!refreshToken){
        return res.status(401).json({
            message: "refresh token not found"
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET)

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    })

    if(!session){
        return res.status(401).json({
            message: "Invalid refresh token"
        })
    }

    const accessToken = jwt.sign({
        id: decoded.id
    }, config.JWT_SECRET,
    {
        expiresIn: "15m"
    })

    const newRefreshToken = jwt.sign({
        id: decoded.id
    }, config.JWT_SECRET, {
        expiresIn: "7d"
    })

    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex")

    session.refreshTokenHash = newRefreshTokenHash
    await session.save()

    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    res.status(200).json({
        message: "access Token refreshed successfully",
        accessToken
    })

}

export async function logout(req, res) {
    const refreshToken = req.cookies.refreshToken

    if(!refreshToken){
        return res.status(400).json({
            message: "refresh Token not found"
        })
    }

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false
    })

    if(!session) {
        return res.status(400).json({
            message: "Invalid refresh token"
        })
    }

    session.revoked = true
    await session.save()

    res.clearCookie("refreshToken")

    res.status(200).json({
        message: "Logged Out successfully"
    })

}

export async function logoutAll(req, res) {
    
    const refreshToken = req.cookies.refreshToken

    if(!refreshToken){
        return res.status(400).json({
            message: "refresh token not found"
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET)

    await sessionModel.updateMany({
        user: decoded.id,
        revoked: false
    }, {
        revoked: true
    })

    res.clearCookie("refreshToken")

    res.status(200).json({
        message: "logged out from all devices"
    })

}

export async function login(req, res) {
    
    const { email, password } = req.body

    if(!(email || password)){
        return res.status(400).json({
            message: "Invalid Credentialls"
        })
    }

    const user = await userModel.findOne({email})

    if(!user){
        return res.status(401).json({
            message: "Invalid Credentialls"
        })
    }

    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex")

    const isPasswordValid = hashedPassword === user.password

    const refreshToken = jwt.sign({
        id: user._id
    }, config.JWT_SECRET, {
        expiresIn: "7d"
    })

    const hashedRefreshToken = crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session = await sessionModel.create({
        user: user._id,
        refreshTokenHash: hashedRefreshToken,
        ip: req.ip,
        userAgent: req.headers["user-agent"]
    })

    if(!session){
        return res.status(401).json({
            message: "Invalid session"
        })
    }

    const accessToken = jwt.sign({
        id: user._id,
        sessionId: session._id
    }, config.JWT_SECRET, {
        expiresIn: "15m"
    })

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    res.status(200).json({
        message: "logged in successfully",
        user: {
            username: user.username,
            email: user.email
        },
        accessToken
    })
}
