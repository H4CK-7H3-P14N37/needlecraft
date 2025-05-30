import os
import json

CONFIG_DIR = os.path.expanduser("~/.config/needlecraft")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    return {}

def get_api_key(service: str) -> str | None:
    """
    Get the API key for a given service.
    Priority: ENV var > config file > None
    """
    env_var = service.upper()
    if env_var in os.environ:
        return os.environ[env_var]

    config = load_config()
    return config.get(service)

def save_api_key(service: str, key: str):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    config = load_config()
    config[service] = key
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)