# MSA
Hello (Hi)

## Author

Microservice attack simulation was created in 2026 by Linards Ruseckis.

Built with [Cookiecutter](https://github.com/cookiecutter/cookiecutter) and the [audreyfeldroy/cookiecutter-pypackage](https://github.com/audreyfeldroy/cookiecutter-pypackage) project template.

# Features

* TODO
* src\MSA\scenarios -> tls, secretmanagment, dos attack + ?
* same zem config\scenarios (3 imitacijas scenariji)
* .html/xml atskaite -> izpildes laiks/parklajums u.c pec bakalaura metrikam
* vel gui uzlabojumi
* viegla CI/CD integracija *seit vel japadoma
* validacija reala microserivce arhitektura (no LC projekta)
* cleanup ar nevajadzigo no cookiecutter + bug fixes gui logikai

## Documentation

* hello (hi)
* defaulta:
python -m MSA.gui
___
python -m MSA.core.engine --scenario config\scenarios\jwt_manipulation.yaml
python -m MSA.core.engine --scenario config\scenarios\dos_attack.yaml
python -m MSA.core.engine --scenario config\scenarios\sql_injection.yaml
python -m MSA.core.engine --scenario config\scenarios\tls_downgrade.yaml
python -m MSA.core.engine --scenario config\scenarios\secret_leak.yaml
___
venv problemainas:
deactivate
Remove-Item -Recurse -Force venv
python -m venv venv
pip install .
.\venv\Scripts\Activate.ps1
pip install -e .


## Motivācijai
😭😊👋💀✅🤩🤗
