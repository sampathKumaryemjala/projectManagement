import app from './app.js'
import dotenv from "dotenv"
dotenv.config({
    path:"./.env"
})

const port = process.env.PORT || 5000


app.get('/instagram',(req,res)=>{
    res.send('Hello World! on tthe ')
})
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
