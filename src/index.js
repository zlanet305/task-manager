const express = require('express');
require("./db/mongoose.js");
const userRouter = require('./routers/user');
const taskRouter = require('./routers/task')

const app = express();
const port = process.env.PORT

app.use(express.json());
app.use(userRouter);
app.use(taskRouter);

app.listen(port, () => {
    console.log("Server is up on port" +port);
})


// mongodb+srv://taskapp:<password>@cluster0.5ccmi.mongodb.net/test