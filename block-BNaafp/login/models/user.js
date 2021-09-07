var bcrypt = require('bcrypt');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var userSchema = new Schema({
    name:String,
    email:{type:String,required:true},
    password:{type:String,required:true,minlength:5}
},{timestamps:true});

userSchema.pre('save',async function(next) {
    if(this.password && this.isModified('password')) {
        this.password = await bcrypt.hash(this.password,10);
    }
    next();
});

userSchema.methods.verifyPassword = async function(password) {
    try {
        var result = await bcrypt.compare(password, this.password);
    } catch (error) {
        return error;
    }
    bcrypt.compare();
}

module.exports = mongoose.model('User', userSchema);
