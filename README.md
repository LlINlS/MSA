# MSA

Built with [Cookiecutter](https://github.com/cookiecutter/cookiecutter) and the [audreyfeldroy/cookiecutter-pypackage](https://github.com/audreyfeldroy/cookiecutter-pypackage) project template.

# Uzstādīšana

Klonēt repo ar: 
```
git clone https://github.com/LlINlS/MSA.git
```

Instalē projektu, virtuālo vidi:
```powershell
# PowerShell/ IDE terminal:
python -m venv venv

.\venv\Scripts\Activate.ps1

pip install -e .
```

Komanda `pip install -e .` instalē projektu rediģējamā režīmā kopā ar visām
atkarībām, kas norādītas `pyproject.toml` failā.


# Testēšanas vide*

Testēšanas vidi veido API vārteja (openresty) un divi mikropakalpojumi (`service_a`,
`service_b`), kas darbināti ar Docker Compose. Vide atbalsta divas konfigurācijas:

- **aizsargātā** (`protected`) — visi drošības mehānismi ir ieslēgti;
- **neaizsargātā** (`unprotected`) — drošības mehānismi ir atslēgti.

Konfigurāciju nosaka `.env` fails. Pārslēgšana ir viens solis:


```powershell
# aizsargātā konfigurācija
(no \\test_environment path)
copy .env.protected .env
docker compose up -d --build --force-recreate

# neaizsargātā konfigurācija
copy .env.unprotected .env
docker compose up -d --build --force-recreate
```

## Palaišana

Rīku var palaist ar grafisko lietotāja saskarni:

```powershell
python -m MSA.gui
```

Palaistais testēšanas vides režīms (`protected` / `unprotected`)
atbilstoši ir vizuāli definēts grafiskajā lietotāja saskarnē.

## Rezultāti

Katras izpildes atskaite tiek saglabāta `results/` mapē JSON formātā ar scenārija
identifikatoru un izpildes datuma un laiku nosaukumā, piemēram:
`SC-AUTH-01_20260803_155128.json`.

Atskaitē tiek fiksēts izpildes režīms, izpildes laiks, izpildes paņēmiena rezultāts
(bloķēts / nav bloķēts) un HTTP atbildes kods.


## Projekta struktūra

```
MSA/
├── src/MSA/
│   ├── core/          # izpildes engine
│   ├── scenarios/     # uzbrukuma scenāriji
│   └── metrics/       # metriku fiksēšana un apkopošana
├── config/scenarios/  # scenāriju konfigurācijas (.yaml)
├── test_environment/  # Docker testēšanas vide (gateway, service_a, service_b)
├── results/           # izpildes atskaites (JSON)
└── pyproject.toml
```

## Motivācijai

hi (hello)
