import express from "express"
import authRouter from "./routes/auth.route.js"
import morgan from "morgan"

const app = express()
app.use(express.json())
app.use(morgan("dev"))

app.use("/api/auth", authRouter)


export default app
