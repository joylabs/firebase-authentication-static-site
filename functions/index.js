const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();

const express = require('express');
const cookieParser = require('cookie-parser')();
const cors = require('cors')({origin: true});
const {Storage} = require('@google-cloud/storage');

const app = express();
app.use(cors);
app.use(cookieParser);

const expiresIn = 60 * 60 * 24 * 1000 * 1; // cookie expires in 1 day

const gcs = new Storage();
const bucket = gcs.bucket("fir-auth-example-a4f18.appspot.com");

function serveContent(request, response) {
    var path = request.path;
    if (path == "/favicon.ico") {
        return response.status(404).send('Not Found');
    }
    if (path.endsWith("/")) {
        path += "index.html";
    }
    var file = bucket.file(path);
    file.createReadStream().pipe(response);
}

app.get('/*', (request, response) => {
    const sessionCookie = request.cookies ? request.cookies.__session || '' : '';
    const idToken = request.query.idToken;
    if (sessionCookie) {
        admin.auth().verifySessionCookie(sessionCookie, false /** checkRevoked */).then((decodedClaims) => {
            return serveContent(request, response);
        }).catch(error => {
            // Session cookie is unavailable or invalid. Force user to login.
            return response.redirect('/login.html');
        });
    } else if (idToken) {
        admin.auth().verifyIdToken(idToken)
            .then(function (decodedToken) {
                if (decodedToken.email.endsWith("@gmail.com") && new Date().getTime() / 1000 - decodedToken.auth_time < 5 * 60) {
                    // Create session cookie and set it.
                    admin.auth().createSessionCookie(idToken, {expiresIn}).then((sessionCookie) => {
                        // Set cookie policy for session cookie.
                        const options = {maxAge: expiresIn, httpOnly: true, secure: false};
                        response.cookie('__session', sessionCookie, options);
                        response.redirect('/');
                        response.end();
                    }, error => {
                        return response.redirect('/login.html');
                    });
                } else {
                    return response.redirect('/login.html');
                }
            }).catch(function (error) {
                return response.redirect('/login.html');
            });
    } else {
        return response.redirect('/login.html');
    }
});

exports.authorizeAccess = functions.https.onRequest(app);
