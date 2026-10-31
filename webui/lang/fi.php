<?php
// Finnish texts of the web UI, by their English source text (see lang.php). Keep %s/%d as they are.
// tests/webui_lang_test.php checks that every text the pages use is here.
return [
    // config.php
    'Demo server: every account and its files are deleted %s hours after registration. Do not store anything you need.'
        => 'Demopalvelin: jokainen tili tiedostoineen poistetaan %s tuntia rekisteröinnin jälkeen. Älä tallenna mitään tarpeellista.',
    'Download the app' => 'Lataa sovellus',
    '(Windows, Linux): it encrypts your files and opens your storage.'
        => '(Windows, Linux): se salaa tiedostosi ja avaa tallennustilasi.',
    'Source code' => 'Lähdekoodi',
    'version' => 'versio',

    // dashboard.php: messages
    'To confirm this, sign in again: it is more than 10 minutes since you signed in.'
        => 'Vahvista tämä kirjautumalla uudelleen: kirjautumisestasi on yli 10 minuuttia.',
    'Enter a code from your authenticator app to confirm.' => 'Vahvista syöttämällä koodi todennussovelluksesta.',
    'Could not start two-factor setup.' => 'Kaksivaiheisen tunnistautumisen käyttöönotto ei käynnistynyt.',
    'Could not turn on two-factor.' => 'Kaksivaiheista tunnistautumista ei saatu päälle.',
    'Could not turn off two-factor.' => 'Kaksivaiheista tunnistautumista ei saatu pois päältä.',
    'Could not start adding a passkey.' => 'Pääsyavaimen lisäys ei käynnistynyt.',
    'Could not add the passkey.' => 'Pääsyavainta ei voitu lisätä.',
    'Could not remove the passkey.' => 'Pääsyavainta ei voitu poistaa.',
    'Could not lock the stick.' => 'Tikkua ei voitu lukita.',
    'Could not remove the stick.' => 'Tikkua ei voitu poistaa.',
    'Could not cancel.' => 'Peruminen ei onnistunut.',
    'Deletion failed.' => 'Poisto epäonnistui.',
    'Two-factor authentication is on.' => 'Kaksivaiheinen tunnistautuminen on päällä.',
    'Two-factor authentication is off.' => 'Kaksivaiheinen tunnistautuminen on pois päältä.',
    'Passkey' => 'Pääsyavain',
    'Adding the passkey expired. Start again.' => 'Pääsyavaimen lisäys vanheni. Aloita alusta.',
    'Passkey added. Next time, sign in with it alone.' => 'Pääsyavain lisätty. Ensi kerralla voit kirjautua pelkällä sillä.',
    'Passkey removed.' => 'Pääsyavain poistettu.',
    'Stick locked: its key cannot be opened, even with your password. If you find the stick, connect with it in the app to unlock it.'
        => 'Tikku lukittu: sen avainta ei voi avata edes salasanallasi. Jos löydät tikun, avaa lukitus yhdistämällä sillä sovelluksessa.',
    'Cancelled. If you did not ask for that change, change your password in the app now.'
        => 'Peruttu. Jos et itse pyytänyt muutosta, vaihda salasanasi sovelluksessa heti.',
    'New USB stick key' => 'Uusi USB-tikun avain',
    'Deletion of the account and all data' => 'Tilin ja kaikkien tietojen poisto',
    'Removal of a locked USB stick' => 'Lukitun USB-tikun poisto',

    // dashboard.php: getting started
    'Getting started' => 'Aloitus',
    '%d of %d done' => '%d/%d tehty',
    'Turn on two-factor authentication' => 'Ota kaksivaiheinen tunnistautuminen käyttöön',
    'Required: a code from your phone keeps a stolen password from being enough.'
        => 'Pakollinen: puhelimesi koodi estää pelkän varastetun salasanan käytön.',
    'Add a passkey' => 'Lisää pääsyavain',
    'Recommended: sign in with a fingerprint, face or security key, without typing your password here.'
        => 'Suositeltu: kirjaudu sormenjäljellä, kasvoilla tai turva-avaimella kirjoittamatta salasanaasi tälle sivulle.',
    'Install the app and connect with your USB stick' => 'Asenna sovellus ja yhdistä USB-tikullasi',
    'The app encrypts your files on your own computer and keeps the key on the stick.'
        => 'Sovellus salaa tiedostosi omalla koneellasi ja pitää avaimen tikulla.',

    // dashboard.php: sections and header
    'Overview' => 'Yleiskuva',
    'Sign-in' => 'Kirjautuminen',
    'USB sticks' => 'USB-tikut',
    'Account' => 'Tili',
    'Sections' => 'Osiot',
    'Dashboard' => 'Hallinta',
    'signed in as' => 'kirjautuneena',
    'Sign out' => 'Kirjaudu ulos',
    'Sign in again' => 'Kirjaudu uudelleen',
    'This server requires two-factor authentication. Set it up below; until then your storage cannot be opened from this account.'
        => 'Tämä palvelin vaatii kaksivaiheisen tunnistautumisen. Ota se käyttöön alla; siihen asti tallennustilaasi ei voi avata tällä tilillä.',
    'Waiting changes' => 'Odottavat muutokset',
    'These take effect at the time shown. If you did not ask for one, cancel it and change your password.'
        => 'Nämä tulevat voimaan näytettynä aikana. Jos et itse pyytänyt jotain niistä, peru se ja vaihda salasanasi.',
    'Cancel' => 'Peru',
    "The record of this server's escrow settings has been tampered with. Ask your administrator what changed."
        => 'Tämän palvelimen avaintalletuksen asetusten lokia on peukaloitu. Kysy ylläpitäjältä, mitä on muutettu.',

    // dashboard.php: storage
    'Storage' => 'Tallennustila',
    '%s used' => '%s käytetty',
    'of %s' => '/ %s',
    '%s free (%s%% used)' => '%s vapaana (%s %% käytetty)',
    'Storage almost full: remove files or ask for more space.' => 'Tila on lähes täynnä: poista tiedostoja tai pyydä lisää tilaa.',
    'Storage use is shown once two-factor authentication is on.' => 'Tilan käyttö näkyy, kun kaksivaiheinen tunnistautuminen on päällä.',
    'Your files are encrypted on your own computer. Open them with the CryptStorage app; this page never shows what is stored.'
        => 'Tiedostosi salataan omalla koneellasi. Avaa ne CryptStorage-sovelluksella; tämä sivu ei koskaan näytä, mitä on tallennettu.',

    // dashboard.php: escrow
    'Escrow is on' => 'Avaintalletus on päällä',
    'Your organisation holds a sealed copy of your storage key, so its administrators can read your files.'
        => 'Organisaatiollasi on sinetöity kopio tallennustilasi avaimesta, joten sen ylläpitäjät voivat lukea tiedostosi.',
    'Organisation key' => 'Organisaation avain',
    'Your copy sealed to' => 'Kopiosi sinetöity avaimelle',
    'The app on your computer checks these against what it remembers on your stick and warns you if they change.'
        => 'Koneesi sovellus vertaa näitä tikulle tallennettuihin tietoihin ja varoittaa, jos ne muuttuvat.',
    'Details' => 'Lisätiedot',
    'Recovery and escrow' => 'Palautus ja avaintalletus',
    'The escrow state could not be read.' => 'Avaintalletuksen tilaa ei voitu lukea.',
    '<strong>Escrow is ON for you.</strong> Your organisation holds a sealed copy of your storage key, so its administrators can read your files.'
        => '<strong>Avaintalletus on PÄÄLLÄ sinulle.</strong> Organisaatiollasi on sinetöity kopio tallennustilasi avaimesta, joten sen ylläpitäjät voivat lukea tiedostosi.',
    '<strong>Escrow is OFF for you.</strong> No copy of your storage key is held by anyone else. Nothing is sealed for you without your consent in the app.'
        => '<strong>Avaintalletus on POIS sinulta.</strong> Kenelläkään muulla ei ole kopiota tallennustilasi avaimesta. Mitään ei sinetöidä ilman suostumustasi sovelluksessa.',
    'Server policy' => 'Palvelimen käytäntö',
    'Settings unchanged since' => 'Asetukset muuttumattomina alkaen',

    // dashboard.php: two-factor
    'Two-factor authentication' => 'Kaksivaiheinen tunnistautuminen',
    'Save your backup codes now' => 'Tallenna varakoodisi nyt',
    'Each code works once if you lose your phone. They are shown only once.'
        => 'Kukin koodi toimii kerran, jos kadotat puhelimesi. Ne näytetään vain tämän kerran.',
    'On' => 'Päällä',
    'Off' => 'Pois päältä',
    'Turning it off needs a code (not possible when the server requires it).'
        => 'Poistaminen käytöstä vaatii koodin (ei mahdollista, jos palvelin vaatii sen).',
    'Code or backup code' => 'Koodi tai varakoodi',
    'Turn off' => 'Poista käytöstä',
    'Open your authenticator app (for example Google Authenticator, Microsoft Authenticator or Aegis) and add an account.'
        => 'Avaa todennussovelluksesi (esimerkiksi Google Authenticator, Microsoft Authenticator tai Aegis) ja lisää uusi tili.',
    'Scan this QR code with the app:' => 'Skannaa tämä QR-koodi sovelluksella:',
    'QR code for the authenticator app' => 'QR-koodi todennussovellukseen',
    'Cannot scan? Choose to enter a key by hand in the app and type or copy this key:'
        => 'Eikö skannaus onnistu? Valitse sovelluksessa avaimen syöttö käsin ja kirjoita tai kopioi tämä avain:',
    'Key for the authenticator app' => 'Avain todennussovellukseen',
    'Copy' => 'Kopioi',
    'Copied' => 'Kopioitu',
    'The spaces are only for reading; the app accepts the key with or without them.'
        => 'Välilyönnit ovat vain lukemisen helpottamiseksi; sovellus hyväksyy avaimen niiden kanssa tai ilman.',
    'Type the 6-digit code the app shows, and the 8-digit code we sent to your e-mail.'
        => 'Syötä sovelluksen näyttämä 6-numeroinen koodi ja sähköpostiisi lähetetty 8-numeroinen koodi.',
    '6-digit code from the app' => '6-numeroinen koodi sovelluksesta',
    '8-digit code from the e-mail' => '8-numeroinen koodi sähköpostista',
    'Confirm and turn on' => 'Vahvista ja ota käyttöön',
    'Adds a code from your phone to signing in, so a stolen password alone is not enough.'
        => 'Lisää kirjautumiseen puhelimesi koodin, joten pelkkä varastettu salasana ei riitä.',
    'Set up' => 'Ota käyttöön',

    // dashboard.php: passkeys
    'Passkeys' => 'Pääsyavaimet',
    'Set up two-factor authentication first. A passkey then lets you sign in with Face ID, a fingerprint or your phone instead of typing a code; the authenticator app stays as the fallback.'
        => 'Ota ensin käyttöön kaksivaiheinen tunnistautuminen. Pääsyavaimella voit sen jälkeen kirjautua Face ID:llä, sormenjäljellä tai puhelimella koodin kirjoittamisen sijaan; todennussovellus jää varatavaksi.',
    'Now confirm on this device, or choose your phone and scan the QR code.'
        => 'Vahvista nyt tällä laitteella, tai valitse puhelin ja skannaa QR-koodi.',
    'Create passkey' => 'Luo pääsyavain',
    'Sign in with Face ID, a fingerprint or your phone instead of typing a code, and sign in to this page with the passkey alone, without your password. Recommended; keep the authenticator app as the fallback.'
        => 'Kirjaudu Face ID:llä, sormenjäljellä tai puhelimella koodin kirjoittamisen sijaan, ja tälle sivulle pelkällä pääsyavaimella ilman salasanaa. Suositeltu; pidä todennussovellus varatapana.',
    'used %s' => 'käytetty %s',
    'not used yet' => 'ei vielä käytetty',
    'Code (if asked)' => 'Koodi (jos kysytään)',
    'Remove' => 'Poista',
    'Name' => 'Nimi',
    'e.g. iPhone' => 'esim. iPhone',
    'Code from the app' => 'Koodi sovelluksesta',
    '(not needed within 5 minutes of signing in)' => '(ei tarvita 5 minuuttiin kirjautumisesta)',

    // dashboard.php: sticks
    'No stick is protected by the server yet. The app does it the next time you connect.'
        => 'Palvelin ei vielä suojaa yhtään tikkua. Sovellus tekee sen, kun seuraavan kerran yhdistät.',
    'The key on each stick also needs a secret this server keeps. If you lose a stick, lock it here: its key cannot be opened at once, even with your password. If you find it, connect with it in the app to unlock it. Removing a stick for good waits like deleting the account, and you get an e-mail with a cancel link.'
        => 'Jokaisen tikun avain tarvitsee myös salaisuuden, jota tämä palvelin säilyttää. Jos kadotat tikun, lukitse se tästä: sen avainta ei voi heti avata edes salasanallasi. Jos löydät sen, avaa lukitus yhdistämällä sillä sovelluksessa. Tikun lopullinen poisto odottaa kuten tilin poisto, ja saat sähköpostiin peruutuslinkin.',
    'locked, removed on %s UTC' => 'lukittu, poistetaan %s UTC',
    'locked: unlock it by connecting with it in the app' => 'lukittu: avaa lukitus yhdistämällä sillä sovelluksessa',
    'Lost? Lock it' => 'Kadonnut? Lukitse',
    'Remove for good' => 'Poista lopullisesti',

    // dashboard.php: account
    'Username' => 'Käyttäjätunnus',
    'Email' => 'Sähköposti',
    'Member since' => 'Jäsen alkaen',
    'Last login' => 'Viimeksi kirjautunut',
    'Delete account' => 'Poista tili',
    'Permanently deletes your account and all encrypted data after a waiting period, during which you can cancel. After that it is <strong>irreversible</strong>: your data cannot be recovered.'
        => 'Poistaa tilisi ja kaikki salatut tiedot pysyvästi odotusajan jälkeen; odotusaikana voit perua. Sen jälkeen poisto on <strong>peruuttamaton</strong>: tietojasi ei voi palauttaa.',
    'Delete account and all data' => 'Poista tili ja kaikki tiedot',
    'Are you absolutely sure? All your data will be deleted when the waiting period ends.'
        => 'Oletko aivan varma? Kaikki tietosi poistetaan, kun odotusaika päättyy.',

    // index.php
    'Password changed. Please sign in again.' => 'Salasana vaihdettu. Kirjaudu uudelleen.',
    'Your account and storage were deleted.' => 'Tilisi ja tallennustilasi poistettiin.',
    'This sign-in link did not work. Start again in the app.' => 'Kirjautumislinkki ei toiminut. Aloita alusta sovelluksessa.',
    'Enter your username.' => 'Syötä käyttäjätunnuksesi.',
    'Passkey sign-in is not available.' => 'Pääsyavaimella kirjautuminen ei ole käytettävissä.',
    'The passkey sign-in expired. Try again.' => 'Pääsyavainkirjautuminen vanheni. Yritä uudelleen.',
    'Passkey sign-in failed:' => 'Pääsyavainkirjautuminen epäonnistui:',
    'Passkey sign-in failed.' => 'Pääsyavainkirjautuminen epäonnistui.',
    'Login failed.' => 'Kirjautuminen epäonnistui.',
    'The sign-in expired. Sign in again.' => 'Kirjautuminen vanheni. Kirjaudu uudelleen.',
    'Sign-in failed.' => 'Kirjautuminen epäonnistui.',
    'The passkey sign-in expired. Sign in again.' => 'Pääsyavainkirjautuminen vanheni. Kirjaudu uudelleen.',
    'Account created. Check your e-mail to verify your address, then sign in.'
        => 'Tili luotu. Vahvista osoitteesi sähköpostiin tulleella linkillä ja kirjaudu sitten sisään.',
    'Next: install the CryptStorage app and run cryptclient setup.'
        => 'Seuraavaksi: asenna CryptStorage-sovellus ja aja cryptclient setup.',
    'Registration failed.' => 'Rekisteröinti epäonnistui.',
    'Signing in as %s' => 'Kirjaudutaan käyttäjänä %s',
    'Use passkey' => 'Käytä pääsyavainta',
    'Fingerprint, face, PIN, security key or your phone.' => 'Sormenjälki, kasvot, PIN, turva-avain tai puhelimesi.',
    'Start over' => 'Aloita alusta',
    'or' => 'tai',
    'Code from your authenticator app' => 'Koodi todennussovelluksesta',
    '(or a backup code)' => '(tai varakoodi)',
    'Verify →' => 'Vahvista →',
    'Sign in' => 'Kirjaudu',
    'Register' => 'Rekisteröidy',
    'Sign in with passkey →' => 'Kirjaudu pääsyavaimella →',
    'No passkey yet? Run <code>cryptclient web-login</code> on your computer: the app signs you in here without your password.'
        => 'Ei vielä pääsyavainta? Aja koneellasi <code>cryptclient web-login</code>: sovellus kirjaa sinut tänne ilman salasanaa.',
    'Sign in with your password instead' => 'Kirjaudu mieluummin salasanalla',
    'Typing your password here trusts this server: it also sends this page, and a compromised server could read the password and open your files. Prefer a passkey or the app.'
        => 'Kun kirjoitat salasanasi tähän, luotat tähän palvelimeen: se lähettää myös tämän sivun, ja murrettu palvelin voisi lukea salasanan ja avata tiedostosi. Käytä mieluummin pääsyavainta tai sovellusta.',
    'Creating the account here sends your password through a page this server controls. If you do not fully trust the server, create it with the app instead (<code>cryptclient setup</code>).'
        => 'Kun luot tilin tässä, salasanasi kulkee sivun kautta, jota tämä palvelin hallitsee. Jos et luota palvelimeen täysin, luo tili sovelluksella (<code>cryptclient setup</code>).',
    'Password' => 'Salasana',
    'Minimum 12 characters. The app gives you a recovery code when it sets up your storage: keep it, it is the only way back if you forget your password.'
        => 'Vähintään 12 merkkiä. Sovellus antaa palautuskoodin, kun se luo tallennustilasi: säilytä se, se on ainoa tie takaisin, jos unohdat salasanasi.',
    'Confirm password' => 'Vahvista salasana',
    'Your files are encrypted with this password. We cannot reset it for you: if you forget it, only the recovery code from the app brings your files back.'
        => 'Tiedostosi salataan tällä salasanalla. Emme voi nollata sitä: jos unohdat sen, vain sovelluksen antama palautuskoodi tuo tiedostosi takaisin.',
    'Sign in →' => 'Kirjaudu →',
    'Create account →' => 'Luo tili →',
    'Forgot your password?' => 'Unohditko salasanasi?',
    'Your browser could not prepare the password securely. Allow scripts for this page, or use a current browser.'
        => 'Selaimesi ei pystynyt käsittelemään salasanaa turvallisesti. Salli tämän sivun skriptit tai käytä ajantasaista selainta.',

    // passkey-approve.php
    'Approve sign-in' => 'Hyväksy kirjautuminen',
    'Approve sign-in to the %s app' => 'Hyväksy kirjautuminen %s-sovellukseen',
    'This link is not complete. Start the sign-in again in the app.' => 'Linkki ei ole kokonainen. Aloita kirjautuminen uudelleen sovelluksessa.',
    'The app on this computer is signing in as %s. Approve only if you just started it yourself.'
        => 'Tämän koneen sovellus kirjautuu käyttäjänä %s. Hyväksy vain, jos käynnistit sen juuri itse.',
    'Approve with passkey' => 'Hyväksy pääsyavaimella',
    'Face ID, fingerprint, a security key, or your phone (scan the QR code).'
        => 'Face ID, sormenjälki, turva-avain tai puhelimesi (skannaa QR-koodi).',

    // recover.php
    'Recover account' => 'Palauta tili',
    'Your files are encrypted on your own computer, so the password cannot be reset here: the server never has it.'
        => 'Tiedostosi salataan omalla koneellasi, joten salasanaa ei voi nollata täällä: palvelimella ei koskaan ole sitä.',
    'Open the CryptStorage app and run <code>cryptclient recover</code>. It asks for the <strong>recovery code</strong> you wrote down when you set up your storage, and lets you choose a new password. Your files stay intact.'
        => 'Avaa CryptStorage-sovellus ja aja <code>cryptclient recover</code>. Se kysyy <strong>palautuskoodia</strong>, jonka kirjoitit muistiin tallennustilaa luodessasi, ja antaa valita uuden salasanan. Tiedostosi säilyvät ennallaan.',
    'If you never wrote the code down and your organisation keeps a recovery copy, ask your administrator.'
        => 'Jos et kirjoittanut koodia muistiin ja organisaatiollasi on palautuskopio, kysy ylläpitäjältä.',
    'Back to sign in' => 'Takaisin kirjautumiseen',

    // cancel.php, verify-email.php
    'Cancel a change' => 'Peru muutos',
    'Cancel a change to your account' => 'Peru tiliisi tehtävä muutos',
    'This link is not complete. Open it again from the e-mail.' => 'Linkki ei ole kokonainen. Avaa se uudelleen sähköpostista.',
    'Someone asked for a new USB stick key or for the deletion of your account. If it was not you, cancel it here, then change your password.'
        => 'Joku pyysi uutta USB-tikun avainta tai tilisi poistoa. Jos se et ollut sinä, peru se tästä ja vaihda sitten salasanasi.',
    'Cancel the change' => 'Peru muutos',
    'Could not verify the address.' => 'Osoitetta ei voitu vahvistaa.',
    'Verify e-mail' => 'Vahvista sähköposti',
    'Verify your e-mail address' => 'Vahvista sähköpostiosoitteesi',

    // assets/passkey.js, assets/derive.js
    'This browser does not support passkeys. Use another way to sign in.'
        => 'Tämä selain ei tue pääsyavaimia. Kirjaudu jollain toisella tavalla.',
    'Follow the prompt of your browser or phone…' => 'Seuraa selaimen tai puhelimen ohjeita…',
    'Cancelled, timed out, or no passkey for this account here. Try again, or use another way.'
        => 'Peruttu, aikakatkaisu tai tälle tilille ei ole pääsyavainta täällä. Yritä uudelleen tai käytä toista tapaa.',
    'The passkey did not work (%s). Try again, or use another way.'
        => 'Pääsyavain ei toiminut (%s). Yritä uudelleen tai käytä toista tapaa.',
    'Preparing your password securely…' => 'Käsitellään salasanaa turvallisesti…',
    'The password must be at least %s characters.' => 'Salasanan on oltava vähintään %s merkkiä.',
    'The two passwords do not match.' => 'Salasanat eivät täsmää.',
    'This browser cannot prepare your password securely. Use a current browser.'
        => 'Tämä selain ei pysty käsittelemään salasanaa turvallisesti. Käytä ajantasaista selainta.',
];
