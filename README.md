# MSA

## Author

Microservice attack simulation was created in 2026 by Linards Ruseckis.

Built with [Cookiecutter](https://github.com/cookiecutter/cookiecutter) and the [audreyfeldroy/cookiecutter-pypackage](https://github.com/audreyfeldroy/cookiecutter-pypackage) project template.

# Atkaribu instalacija*

* TODO

# Testēšanas vide*

* TODO
  

## Documentation

* hello (hi)
* default:
python -m MSA.gui
___
python -m MSA.core.engine --scenario config\scenarios\jwt_manipulation.yaml
python -m MSA.core.engine --scenario config\scenarios\dos_attack.yaml
python -m MSA.core.engine --scenario config\scenarios\sql_injection.yaml
python -m MSA.core.engine --scenario config\scenarios\tls_downgrade.yaml
python -m MSA.core.engine --scenario config\scenarios\secret_leak.yaml
___
MISC:
deactivate
Remove-Item -Recurse -Force venv
python -m venv venv
pip install .
.\venv\Scripts\Activate.ps1
pip install -e .


## Motivācijai

