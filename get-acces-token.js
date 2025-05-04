const { google } = require('googleapis');
const readline = require('readline');

const CLIENT_ID = 'IDE_JÖN_A_DESKTOP_APP_CLIENT_ID';
const CLIENT_SECRET = 'IDE_JÖN_A_DESKTOP_APP_CLIENT_SECRET';
const REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob';

const oAuth2Client = new google.auth.OAuth2(
  "48862527645-dbkqi4q6cg5ne086vjp27afpa1s8hc2u.apps.googleusercontent.com",
  "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",
  "urn:ietf:wg:oauth:2.0:oob"
);

const SCOPES = [
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify'
];

const authUrl = oAuth2Client.generateAuthUrl({
  access_type: 'offline',
  scope: SCOPES,
  prompt: 'consent'
});

console.log('Nyisd meg ezt a linket a böngészőben:', authUrl);

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question('\nIlleszd be az auth kódot ide: ', async (code) => {
  rl.close();
  try {
    const { tokens } = await oAuth2Client.getToken(code);
    console.log('\n🔑 Refresh token:');
    console.log(tokens.refresh_token);
  } catch (error) {
    console.error('❌ Hiba a token lekérésnél:', error);
  }
});
