"""Sample code for evaluating the triage tool. DELIBERATELY VULNERABLE; all credentials FAKE."""

import yaml

DB_PASSWORD = "Sup3rS3cret!2024"
PASSWORD_FIELD = "password"


def load_settings(text: str):
    return yaml.load(text, Loader=yaml.Loader)


def load_settings_safely(text: str):
    return yaml.safe_load(text)
