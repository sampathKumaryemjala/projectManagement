import express from 'express'
import cors from 'cors'
import healthCheckRouter from './routes/healthcheck.routes.js'


const app=express();
//basic configuration
app.use(express.json({limit:'16kb'}))
app.use(express.urlencoded({extended:true,limit:'16kb'}))
app.use(express.static("public"))

//cors configuration
app.use(cors({
    origin:process.env.CORS_ORIGIN?.split(",") || 'http://localhost:5173',
    credentials:true, // to work with cookies 
    methods:['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
    allowedHeaders:['Content-Type','Authorization'] //
}))

//import the routes 

app.use("/api/v1/healthcheck",healthCheckRouter)
app.get("/",(req,res)=>{
res.send("klkal")
})

export default app