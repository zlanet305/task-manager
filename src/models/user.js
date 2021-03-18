const mongoose = require('mongoose');
const validator = require('validator');
const bycrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Task = require('./tasks')

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    age: {
        type: Number,
        default: 0,
        validate(value) {
            if(value < 0) {
                throw new Error('Age must be a positive number')
            }
        }
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        validate(value) {
            if(!validator.isEmail(value)){
                throw new Error('Email is invalid');
            }
        }
    },
    password: {
        type: String,
        required: true,
        trim: true,
        validate(value){
            if(value.length<7){
                throw new Error('Password should contain more than 6 letters')
            }
            if(value.includes("password")){
                throw new Error('Password cannot be password')
            }
        }
    },
    tokens: [{
        token : {
            type: String,
            required: true
        }
    }],
    avatar: {
        type: Buffer
    }
}, {
    timestamps: true
})

userSchema.virtual("tasks", {
    ref: "tasks",
    localField: "_id",
    foreignField: "owner",
    });

userSchema.methods.generateAuthToken = async function (req, res){
    const user = this;
    const token = jwt.sign({_id: user._id.toString()}, process.env.JWT_SECRET)
    user.tokens = user.tokens.concat({token})
    await user.save();
    return token;
}

userSchema.methods.toJSON = function (){
    const user = this;
    const userObject = user.toObject()

    delete userObject.password
    delete userObject.tokens
    delete userObject.avatar
    return userObject
}

userSchema.statics.findByCredentials = async (email, password) => {
    const user = await User.findOne({ email })
    if(!user){
        throw new Error('Unable to login')
    }

    const isMatch = await bycrypt.compare(password, user.password)
    if(!isMatch){
        throw new Error("Unable to login");
    }

    return user
}

//hash the user password before saving
userSchema.pre('save', async function(next){
    if(this.isModified('password')){
        this.password = await bycrypt.hash(this.password, 8)
    }
    next();
})

const User = mongoose.model('User', userSchema)

module.exports = User;