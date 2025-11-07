import mongoose from 'mongoose'

const connectDB = async ()=>{
    try {
        await mongoose.connect(process.env.MONGO_URI)
        console.log("mongoDB is connected ")
    } catch (error) {
        console.log("MongoDB connection error ",error)
        process.exit(1) //exit if the connection failed
    }
}

export default connectDB