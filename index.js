const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const userModel = require('./models/user');
const postModel = require('./models/post');
const upload = require('./utils/multer');
const port = 4000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.render('register', {errorMessage: null});
})

app.get('/login', (req, res) => {
    res.render('login', {errorMessage: null});
})

app.post('/register', async (req, res) => {
    const {username, fullname, age, email, password} = req.body;
    const existingUser = await userModel.findOne({email})
    if(existingUser) return res.render('register', {errorMessage: email})
    await bcrypt.genSalt(10,(err,salt) => {
        bcrypt.hash(password, salt, async (err,hash) =>{
            await userModel.create({
                username,
                fullname,
                age,
                email,
                password: hash
            })
            const token = jwt.sign({email}, 'secret')
            res.cookie('token', token);
            res.redirect(`/profile`)
        })
    })
})

app.get('/login', (req, res) => {
    res.render('login');
})

app.post('/login', async (req, res) => {
    const {email, password} = req.body;
    const user = await userModel.findOne({email});
    if(!user) return res.render('login', {errorMessage: 'Username Or Password was incorrect'});
    await bcrypt.compare(password, user.password, (err, result) => {
        if(!result){
            return res.render('login', {errorMessage: 'Username Or Password was incorrect'});
        }else{
            const token = jwt.sign({email},'secret')
            res.cookie('token', token);
            res.redirect(`/profile`);
        }
    });
})

function isLoggedIn(req, res, next) {
    const token = req.cookies.token;
    if(!token) {
        res.redirect('/login')
    }
    jwt.verify(req.cookies.token, 'secret', (err, decoded)=>{
        if(err) return res.redirect('/login')
            req.user = decoded;
            next();
    });
}

app.get('/profile', isLoggedIn, async (req, res) => {
    const user = await userModel.findOne({email: req.user.email}).populate('posts');
    res.render('profile', {user});
})
app.post('/post', isLoggedIn, async (req, res) => {
    const user = await userModel.findOne({email: req.user.email})
    const {content} = req.body;
    let post = await postModel.create({
        user: user._id,
        content: content
    })
    user.posts.push(post._id);
    await user.save();
    res.redirect('/profile')
})

app.get('/delete/:id' ,isLoggedIn , async (req, res) => {
    await postModel.findOneAndDelete({_id: req.params.id});
    res.redirect('/profile');
})

app.get('/edit/:id' ,isLoggedIn , async (req, res) => {
    let post = await postModel.findOne({_id: req.params.id});
    let user = await userModel.findOne({_id: post.user})
    console.log(post);
    console.log(user);
    res.render('post', {post, user});
})

app.post('/edit/:id', isLoggedIn, async (req, res) => {
    const {content} = req.body;
    await postModel.findOneAndUpdate({_id:req.params.id}, {content})
    res.redirect('/profile');
})

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
})

app.get('/profile/update/:id', isLoggedIn, async (req, res) => {
    const user = await userModel.findOne({_id: req.params.id});
    res.render('updateProfile', {user});
})

app.post('/profile/update/:id', isLoggedIn, upload.single('image'), async (req, res) => {
    const{fullname} = req.body;
    const user = await userModel.findOneAndUpdate({_id: req.params.id}, {fullname},{new : true});
    if(req.file){
        user.image = req.file.filename;
        await user.save();
    }
    res.redirect('/profile');

})

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
})