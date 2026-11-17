# Suivi Médocs

Petite PWA hors ligne pour suivre une prise de médicaments (prises programmées, minuteurs, rappels).
Les données du traitement sont chiffrées (`data.enc`, AES-256-GCM + PBKDF2) ; l'historique reste dans le navigateur.

Mettre à jour les données : modifier `meds.json` (local, non versionné) puis `node encrypt.mjs`.
