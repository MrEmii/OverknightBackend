const express = require('express');
var https = require('https')
const bodyParser = require('body-parser');
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt-nodejs');
const base64ToImage = require('./BaseImage');
const MongoClient = require('mongodb').MongoClient;

const mongoURI = "mongodb://mremii:Emirhassanali10@ds056789.mlab.com:56789/overknight";

const mongodb = new MongoClient(mongoURI, { useNewUrlParser: true })

var userDb;
var homeHeader;
var homePosts;
var shop;
var discounts;

var accountsTokens = [];

const app = express();

app.set('port', process.env.PORT || 2053);
app.use(cors())
app.use(morgan('dev'));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

const mailjet = require('node-mailjet')
    .connect('d88e3842becfb3a92362a6a66bc45f64', '03c642f460b7531a450efb88430555ed');

app.get("/", (req, res) => {
    res.send("hola")
})

app.post("/signup", (req, res) => {
    let { email, username, lastnane, number, photo, password } = req.body;
    getUserByEmail(email).then((user) => {
        res.send({ error: "Email exists" })
    }, () => {
        var base64Str = photo;
        var path = './images/users/';
        var optionalObj = { 'fileName': email + username + ".png", 'type': 'png' };

        var picFile = base64ToImage(base64Str, path, optionalObj);

        var token = (Math.random().toString(36).substr(2)) + (Math.random().toString(36).substr(2));
        userDb.insertOne({
            username: username,
            last_nane: lastnane,
            email: email,
            password: bcrypt.hashSync(password, bcrypt.genSaltSync(8)),
            verified: false,
            verifiedToken: token,
            last_login: "",
            signupdate: Date.now(),
            number: number,
            payments: [],
            state: undefined,
            city: undefined,
            county: undefined,
            country: "Mexico",
            zip: undefined,
            street: undefined,
            streetcode: undefined,
            depcode: undefined,
            rank: "user"
        }, (err, result) => {
            if (err)
                console.log(err);

            var sendEmail = mailjet.post("send", { 'version': 'v3.1' })

            var Emails = {
                "Messages": [
                    {
                        "From": {
                            "Email": "team@overknight.com.mx",
                            "Name": "OverKnightTeam"
                        },
                        "To": [
                            {
                                "Email": email,
                                "Name": username[0]
                            }
                        ],
                        "TemplateID": 903681,
                        "TemplateLanguage": true,
                        "Subject": "Verifica tu cuenta " + username[0] + "!",
                        "Variables": {
                            "nombre": username[0],
                            "username": username[0],
                            "verificarurl": "https://overknight.com.mx/verify/" + token
                        }
                    }
                ]
            }

            sendEmail.request(Emails).then((handlePostResponse) => {
                console.log("Mail sent to " + email);
                console.log(handlePostResponse.body);

            }).catch((handleError) => {
                console.log(handleError)
            });

            res.send({"success":"logged"});
        })

    })


})

app.post("/valdatediscount", (req, res) => {
    var discount = req.body.code;
    discounts.findOne({ "codigo": discount }, (err, code) => {
        if (err) {
            res.send({ "error": "Hubo un error con el descuento!" })
        }
        if (!code) {
            res.send({ "error": "El código "+discount+" no existe!" })
        }
        if (code) {
            res.send(code)
        }
    })

})

app.post("/signin", (req, res) => {
    var current = new Date().getTime();
    var email = req.body.email;
    var password = req.body.password;
    userDb.findOne({ 'email': email }, (err, user) => {
        if (err) {
            res.send({ error: err })
        }
        if (user) {
            var ress = bcrypt.compareSync(password, user.password);
            if (ress) {
                const exists = accountsTokens.find(a => a.email === user.email);
                if (exists) {
                    console.log(new Date().getTime() - current);
                    console.log((new Date().getTime() - current) / 1000);
                    res.send({ sessionid: exists.sessionid })
                } else {
                    var token = (Math.random().toString(36).substr(2)) + (Math.random().toString(36).substr(2));
                    accountsTokens.push({
                        email: user.email,
                        id: user._id,
                        uuid: user.verifiedToken,
                        username: user.username,
                        lastname: user.last_nane,
                        sessionid: token,
                        photo: "https://overknight.com.mx:2053/data/users/" + user.email + user.username,
                        timestamp: Date.now(),
                        signupdate: user.signupdate,
                        verified: user.verified,
                        rank: user.rank
                    })
                    console.log(new Date().getTime() - current);
                    console.log((new Date().getTime() - current) / 1000);
                    res.send({
                        sessionid: token,
                    });
                    userDb.updateOne({ "email": user.email }, { $set: { "last_login": Date.now() } })
                }
            } else {
                res.send({ error: 1 })
            }
        } else {
            res.send({ error: 1 })
        }

    })

})

app.get("/data/:from/:uuid", (req, res) => {
    var uuid = req.params.uuid + ".png";
    fs.exists("./images/" + req.params.from + "/" + uuid, (exists) => {
        if (!exists) {
            res.status(403).send("Sorry! You can't see that.")
        } else {
            var options = {
                root: path.join(__dirname, 'images/' + req.params.from),
                dotfiles: 'deny',
                headers: {
                    'x-timestamp': Date.now(),
                    'x-sent': true
                }
            }

            var fileName = uuid
            res.sendFile(fileName, options, function (err) {
                if (err) {
                    console.log(err)
                } else {
                    console.log('Sent:', fileName)
                }
            })
        }
    });
})

app.post('/verifiedaccount/account', (req, res) => {
    var token = req.body.token;
    if (token) {
        userDb.findOne({ 'verifiedToken': token }, (err, result) => {
            if (result) {
                if (result.verified) {
                    res.send({ "result": 'is already verified' })
                } else {
                    const exists = accountsTokens.find(a => a.email === result.email);
                    exists.verified = true;
                    userDb.updateOne({ 'verifiedToken': token }, { $set: { 'verified': true } }, (err, ress) => {
                        res.send({ "result": "verified" })
                    })
                }
            } else {
                res.send({ "error": "accounts does exists" })
            }
        })
    }
})

app.post("/updateprofile", (req, res) => {
    var type = req.body.type
    var accesstoken = req.body.accesstoken
    var data = req.body.data

    if (type && accesstoken && data) {
        const exists = accountsTokens.find(a => a.sessionid === accesstoken);
        if (exists) {
            if (type === "image") {
                var base64Str = data;
                var path = './images/users/';
                var optionalObj = { 'fileName': exists.email + exists.username + ".png", 'type': 'png' };

                base64ToImage(base64Str, path, optionalObj);
                res.send({ succes: "Foto cambiada con exito!" })
            } else {
                if (type === "email" || type === "nombre") {
                    var newvar = type === "email" ? data + exists.username : exists.email + data;
                    fs.renameSync("./images/users/" + exists.email + exists.username + ".png" + ".png", "./images/users/" + newvar + ".png")
                } else {
                    userDb.updateOne({ 'email': exists.email }, { $set: { type: data } }, (err, ress) => {
                        if (err) {
                            res.send({ error: "Ocurrio un error! Intentalo más tarde" })
                        }
                        exists[type] = data;
                        res.send({ succes: "Cambios con exito!" })
                    })
                }
            }
        } else {
            res.send({ error: "Accesstoken invalido" })
        }
    }
})

app.post('/authenticate', (req, res) => {
    var sessionid = req.body.sessionid;
    const exists = accountsTokens.find(a => a.sessionid === sessionid);
    if (exists) {
        return res.send(exists)
    } else {
        var err = new Error('Session id not found.');
        err.status = 403;
        return res.send(err);
    }
})


app.post("/post/homeheader", (req, res) => {
    var accessToken = req.body.token;
    var image = req.body.image;
    var description = req.body.description;
    var list = [];
    var accessList = []
    var ip = getClientIP(req).IP;
    if (accessToken == accessList && ip == list) {
        homeHeader.insertOne({
            imagen: image,
            description: description
        }, (err, result) => {
            if (err) {
                res.send(err)
            } else {
                res.send(result)
            }
        })
    }
})

app.post("/post/shopheader", (req, res) => {
    var accessToken = req.body.token;
    var ip = getClientIP(req).IP;
    var image = req.body.data;

    if (accessToken && ip && image) {
        const exists = accountsTokens.find(a => a.sessionid === accessToken);
        if (exists) {
            if (exists.rank === "developer" || exists.rank === "owner") {
                var iplist = [];
                if (iplist.includes(ip)) {

                    var base64Str = data;
                    var path = './images/shopHeader/';
                    var optionalObj = { 'fileName': "Header.png", 'type': 'png' };
                    fs.renameSync("./images/shopHeader/Header.png", "./images/shopHeader/HeaderAt" + new Date.now() + ".png")
                    base64ToImage(base64Str, path, optionalObj);
                    res.send({ succes: "Foto cambiada con exito!" })
                }
            }
        }
    }


})

app.post("/shop", (req, res) => {
    shop.find({}).toArray((err, docs) => {
        var hombre = docs.filter(a => {
            return a.sexo === "hombre"
        })
        var mujer = docs.filter(a => {
            return a.sexo === "mujer"
        })
        var unisex = docs.filter(a => {
            return a.sexo === "unisex"
        })

        var aaa = {
            hombre: hombre,
            mujer: mujer,
            unisex: unisex
        };
        res.send({ shop: aaa })
    })
})

app.post("/get/homeheader", (req, res) => {

    homeHeader.find({}).toArray((err, doc) => {
        if (err) {
            res.send(err)
        }
        var homeHeaders = Array.from(doc)
        res.send({ homeHeaders })
    })
})

function getUserByEmail(email) {
    return new Promise((resolve, reject) => {
        if (email) {
            userDb.findOne({ 'email': email }, (err, result) => {
                if (err) {
                    reject(err)
                }
                if (result) {
                    var user = {
                        username: result.username,
                        usernamelower: result.usernamelower,
                        email: result.email,
                        lastlogin: result.last_login,
                        verified: result.verified,
                        id: result._id,
                        signupdate: result.signupdate,
                        payments: result.payments
                    }
                    resolve(user);
                } else {
                    reject();
                }
            })
        } else {
            reject();
        }
    })
}
function getUser(name) {
    return new Promise((resolve, reject) => {
        if (name) {
            userDb.findOne({ 'usernamelower': name }, (err, result) => {
                if (err) {
                    reject(err)
                }
                if (result) {
                    var user = {
                        username: result.username,
                        usernamelower: result.usernamelower,
                        email: result.email,
                        lastlogin: result.last_login,
                        verified: result.verified,
                        id: result._id,
                        signupdate: result.signupdate,
                        payments: result.payments
                    }
                    resolve(user);
                } else {
                    reject();
                }
            })
        } else {
            reject();
        }
    })
}
var options = {

    key: fs.readFileSync('certs/overknight.com.mx.key'),

    cert: fs.readFileSync('certs/overknight.com.mx.crt'),

    ca: fs.readFileSync('certs/overknight.com.mx.ca-bundle')

};
const httpsServer = https.createServer(options, app);
/*
app.listen(app.get('port'), () => {
    mongodb.connect((err, client) => {
        if (err) {
            console.log(err);
        }
        userDb = client.db('overknight').collection("accounts")
        homeHeader = client.db('overknight').collection("homeHeader")
        shop = client.db('overknight').collection("shop")
        discounts = client.db('overknight').collection("discounts")

        console.log(`Server on port ${app.get('port')}`);
    })
})
*/

httpsServer.listen(app.get('port'), function (smr) {
    if (smr) {
        console.log(smr);
    }
    mongodb.connect((err, client) => {
        if (err) {
            console.log(err);
        }
        userDb = client.db('overknight').collection("accounts")
        homeHeader = client.db('overknight').collection("homeHeader")
        shop = client.db('overknight').collection("shop")
        discounts = client.db('overknight').collection("discounts")

        console.log(`Server on port ${app.get('port')}`);
    })
})

function getClientIP(req) {
    try {
        var IPs = req.headers['x-forwarded-for'] ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            req.connection.socket.remoteAddress;

        if (IPs.indexOf(":") !== -1) {
            IPs = IPs.split(":")[IPs.split(":").length - 1]
        }

        return ({
            IP: IPs.split(",")[0]
        })
    } catch (err) {
        return ({
            message: 'got error'
        });
    }
}