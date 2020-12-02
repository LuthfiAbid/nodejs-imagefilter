//use path module
var path = require('path');
//use express module
var express = require('express');
//use bodyParser middleware
var bodyParser = require('body-parser');
//use session
const session = require('express-session');
//use fs
const fs = require('fs');
//use mysql database
const mysql = require('mysql');
//use bcrypt
const bcrypt = require('bcrypt-nodejs');
const saltRounds = bcrypt.genSaltSync(10);
//use multer
const multer = require('multer');

//use express validator
const expressValidator = require('express-validator');
//use express flash
const flash = require('express-flash');
const app = express();

//use datalize
const { Validator } = require('node-input-validator');
// const datalize = require('datalize');
// const { validationResult } = require('express-validator/check');
const { handlebars } = require('hbs');
//filter file type
const helpers = require('./helpers');

//storage
const storage = multer.diskStorage({
  destination: path.join(__dirname, 'image'),
  filename: function (request, file, cb) {
    cb(null, new Date().getTime() + "_" + file.originalname);
  }
});

//konfigurasi koneksi
const conn = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'crud_db'
});

//connect ke database
conn.connect((err) => {
  if (err) throw err;
  console.log('Mysql Connected...');
});

//set views file
app.set('views', path.join(__dirname, 'views'));
//set view engine
app.set('view engine', 'hbs');

app.use(express.static('image'));
app.use(expressValidator());
//login session
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true,
  cookie: { maxAge: 600000 }
}));

app.use(flash());

app.use(function (req, res, next) {
  res.locals.sessionFlash = req.session.sessionFlash;
  delete req.session.sessionFlash;
  next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
//set folder public sebagai static folder untuk static file
app.use('/assets', express.static(__dirname + '/public'));

//login form
app.get('/login', function (request, response) {
  if (request.session.loggedin == true) {
    if (request.session.role_id == '1') {
      response.redirect('/admin')
    } else {
      response.redirect('/user')
    }
  }
  response.render('login')
});

app.get('/', function (req, res) {
  res.send('404 not found <a href="/login">Login</a>');
})

//proses auth
app.post('/auth', function (request, response) {
  let email = request.body.email;
  let password = request.body.password;
  let sql = ('SELECT password FROM account where email = "' + email + '"');
  conn.query(sql, (err, results) => {
    if (err) throw err;
    if (email && bcrypt.compareSync(password, results[0].password)) {
      conn.query('SELECT * FROM account WHERE email = ? AND password = ?', [email, results[0].password], function (err, results) {
        if(err) throw err;
        if (results.length > 0) {
          request.session.username = results[0].username;
          request.session.userId = results[0].id;
          request.session.loggedin = true;
          request.session.role_id = results[0].id_role;
          if (results[0].id_role == '1') {
            response.redirect('/admin');
          } else {
            response.redirect('/user');
          }
        } else {
          response.send('Incorrect Username and/or Password!');
        }
        response.end();
      });
    } else {
      response.send('Please enter Username and Password!');
      response.end();
    }
  });
});

handlebars.registerHelper("inc", function (value, options) {
  return parseInt(value) + 1;
});

handlebars.registerHelper("format", function (value, options) {
  return new Intl.NumberFormat().format(value)
});

handlebars.registerHelper("isNull", function (value, options) {
  return value === null;
});

//route untuk homepage admin
app.get('/admin', (request, response) => {
  let id = request.session.userId;
  let sql = "SELECT product.*, account.id_role AS role_id FROM product JOIN account ON account.id = product.id_user WHERE product.id_user = '" + id + "'";
  conn.query(sql, (err, result) => {
    if (err) throw err;
    if (request.session.loggedin == undefined || request.session.loggedin == false) {
      request.flash('error', 'Please login before access this page!')
      response.redirect('/login');
    } else {
      if (request.session.role_id == '1') {
        response.render('admin/product_view', {
          results: result,
          data: request.session.username,
          id: request.session.userId,
        });
      } else {
        response.send('You cannot access this page!');
      }
    }
  });
});

//route untuk homepage user
app.get('/user', (request, response) => {
  let id = request.session.userId;
  let sql = "SELECT product.*, account.id_role AS role_id FROM product JOIN account ON account.id = product.id_user WHERE product.id_user = '" + id + "'";
  conn.query(sql, (err, result) => {
    if (err) throw err;
    if (request.session.loggedin == undefined || request.session.loggedin == false) {
      response.redirect('/login');
    } else {
      if (request.session.role_id == '2') {
        response.render('user/product_view', {
          results: result,
          data: request.session.username,
          id: request.session.userId
        });
      } else {
        response.send('You cannot access this page!');
      }
    }
  });
});

//logout
app.get('/logout', (request, response) => {
  request.session.loggedin = false;
  response.redirect('/login');
});

//form register
app.get('/register', function (request, response) {
  let sql = 'SELECT * FROM role';
  conn.query(sql, (err, results) => {
    if (err) throw (err)
    response.render('register', {
      results: results
    })
  })
});

//post register
app.post('/post-register', function (request, response) {
  let email = request.body.email;
  const validate = new Validator(request.body, {
    email: 'required|email',
    username: 'required',
    password: 'required|minLength:3',
    repassword: 'required|same:password'
  });

  conn.query('select 1 from account where email = "' + email + '" order by id limit 1', function (err, res) {
    if (res.length > 0) {
      console.log('Email already exist')
      response.redirect('back')
    } else {
      validate.check().then((matched) => {
        if (matched) {
          var users = {
            email: request.sanitizeBody('email').escape().trim(),
            username: request.sanitizeBody('username').escape().trim(),
            id_role: request.sanitizeBody('role').escape().trim(),
            password: bcrypt.hashSync(request.body.password, saltRounds)
          }
          conn.query('INSERT INTO account SET ?', users, function (err, result) {
            if (err) {
              // req.flash('error', err)
              response.render('register', {
                title: 'Registration Page',
                role: '',
                email: '',
                username: '',
                password: ''
              })
            } else {
              request.flash("success", "You've successfully signup!")
              response.redirect('/login');
            }
          })
        } else {
          request.session.errors = res.send(validate.errors);
          response.render('register', {
            title: 'Registration Page',
            role: request.body.role,
            email: request.body.email,
            username: request.body.username,
            password: ''
          })
        }
      })
    }
  })
});



//route untuk insert data
app.post('/save', (req, res) => {
  let upload = multer({ storage: storage, fileFilter: helpers.imageFilter }).single('image');
  upload(req, res, function (err) {
    if (err) {
      res.send('Image type only!');
    }

    let data = { id_user: req.session.userId, file: req.file.filename, product_name: req.body.product_name, product_price: req.body.product_price };
    let sql = "INSERT INTO product SET ?";
    conn.query(sql, data, (err, results) => {
      if (err) throw err;
      res.redirect('back');
    });
  });
});

//route untuk update data
app.post('/update', (req, res) => {
  let upload = multer({ storage: storage, fileFilter: helpers.imageFilter }).single('file');
  upload(req, res, function (err) {
    if (err) {
      res.send('Image type only!');
    }

    let old = "SELECT file FROM product WHERE product_id =" + req.body.id;
    conn.query(old, (err, results) => {
      if (err) throw err;
      fs.unlink(path.join(__dirname, 'image/' + results[0].file), (err) => {
        if (err) throw err;
        console.log('path file was successfully deleted');
      });
    })

    let data = { id_user: req.session.userId, file: req.file.filename, product_name: req.body.product_name, product_price: req.body.product_price };
    let sql = "UPDATE product SET ? WHERE product_id=" + req.body.id;
    conn.query(sql, data, (err, results) => {
      if (err) throw err;
      res.redirect('back');
    });
  });
});

//route untuk delete data
app.post('/delete', (req, res) => {
  let sql = "DELETE FROM product WHERE product_id=" + req.body.product_id + "";
  conn.query(sql, (err, results) => {
    if (err) throw err;
    res.redirect('back');
  });
});

//server listening
app.listen(8000, () => {
  console.log('Server is running at port 8000');
});