import dotenv from "dotenv"

dotenv.config()

if(!process.env.PORT){
    throw new Error(`Missing port variable`)
} 

if(!process.env.MONGODB_URI){
    throw new Error(`Missing MONGODB_URI variable`)
}

if(!process.env.JWT_SECRET){
    throw new Error(`Missing JWT_SECRET variable`)
}
 
const config = {
    PORT: process.env.PORT,
    MONGODB_URI: process.env.MONGODB_URI,
    JWT_SECRET: process.env.JWT_SECRET
}

export default config
