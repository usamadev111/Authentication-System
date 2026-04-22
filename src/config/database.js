import mongoose from "mongoose";
import config from "./config.js";

async function connectDB () {
    await mongoose.connect(config.MONGODB_URI)

    console.log("Connected to Database Successfully");
    
}

export default connectDB
