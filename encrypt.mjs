#!/usr/bin/env node
// Chiffre meds.json -> data.enc (AES-256-GCM, clé PBKDF2-SHA256 600 000 itérations).
// Usage :  node encrypt.mjs            (demande le mot de passe, chiffre, puis publie sur GitHub)
//          node encrypt.mjs --no-push  (chiffre seulement)
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes, pbkdf2Sync, createCipheriv, createDecipheriv } from 'node:crypto';
import { execSync } from 'node:child_process';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const ITER = 600000;
const dir = fileURLToPath(new URL('.', import.meta.url));

function askHidden(question) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    process.stdout.write(question);
    rl._writeToOutput = () => {};
    rl.question('', answer => { rl.close(); process.stdout.write('\n'); resolve(answer); });
  });
}

const plain = readFileSync(dir + 'meds.json', 'utf8');
JSON.parse(plain); // validate

let pw = process.env.MEDOCS_PW; // tests only
if (!pw) {
  pw = await askHidden('Mot de passe : ');
  const pw2 = await askHidden('Confirme le mot de passe : ');
  if (pw !== pw2) { console.error('✗ Les mots de passe ne correspondent pas.'); process.exit(1); }
}
if (!pw || pw.length < 6) { console.error('✗ 6 caractères minimum.'); process.exit(1); }

const salt = randomBytes(16), iv = randomBytes(12);
const key = pbkdf2Sync(pw, salt, ITER, 32, 'sha256');
const cipher = createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final(), cipher.getAuthTag()]);

// self-check
const d = createDecipheriv('aes-256-gcm', key, iv);
d.setAuthTag(ct.subarray(ct.length - 16));
const back = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8');
if (back !== plain) { console.error('✗ Vérification échouée.'); process.exit(1); }

const out = { v: 1, rev: Date.now().toString(36), iter: ITER,
  salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64') };
writeFileSync(dir + 'data.enc', JSON.stringify(out));
console.log('✓ data.enc créé');

if (!process.argv.includes('--no-push')) {
  const run = c => execSync(c, { cwd: dir, stdio: 'inherit' });
  run('git add data.enc');
  run('git commit -q -m "Mise à jour des données chiffrées"');
  run('git push -q');
  console.log('✓ Publié — en ligne dans ~1 min');
}
