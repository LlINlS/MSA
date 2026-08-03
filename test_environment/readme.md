# hello

## Kā pārslēdz konfigurāciju (viens solis)

# Aizsargātā:

copy .env.protected .env && docker compose up -d --build --force-recreate

# Neaizsargātā:

copy .env.unprotected .env && docker compose up -d --build --force-recreate

(Linux/macOS: cp .env.protected .env)

## SVARĪGI: TLS ssl_verify_disabled (viens papildu solis aizsargātajā režīmā)

Scenārijs izmanto requests.get(..., verify=True). Pašparakstītam sertifikātam host'am tas
jāuztic, citādi aizsargātā režīmā rodas viltus kļūdaini pozitīvs. Pirms TLS scenārija palaišanas:
docker cp <gateway_konteinera_id>:/etc/nginx/certs/server.crt ./server.crt
set REQUESTS_CA_BUNDLE=%CD%\server.crt (Windows)
export REQUESTS_CA_BUNDLE=$PWD/server.crt (Linux/macOS)
Tad palaid TLS scenāriju tajā pašā terminālī. Neaizsargātā režīmā HTTPS porta nav → savienojums
neizdodas → ievainojamība (kā paredzēts).
