const path = require('path');
const {google} = require('googleapis');

// .env betöltése
require('dotenv').config({ path: path.join(__dirname, 'src', '.env') });

async function getAccessToken() {
  try {
    const oAuth2Client = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      'https://developers.google.com/oauthplayground'
    );

    oAuth2Client.setCredentials({
      refresh_token: process.env.GMAIL_REFRESH_TOKEN.trim()
    });

    console.log('Új access token generálása...');
    const {token} = await oAuth2Client.getAccessToken();
    return token;
  } catch (error) {
    console.error('Hiba történt:', error.message);
    console.log('\nTIPP: Próbálj új refresh tokent generálni:');
    console.log('1. Menj a https://developers.google.com/oauthplayground oldalra');
    console.log('2. Válaszd ki a Gmail API-t');
    console.log('3. Generálj új refresh tokent');
    console.log('4. Frissítsd a .env fájlt');
    throw error;
  }
}

getAccessToken()
  .then(token => {
    console.log('\n=== SIKERES TOKEN GENERÁLÁS ===');
    console.log('Access token:', token);
    console.log('===============================');
  })
  .catch(() => {
    process.exit(1);
  });