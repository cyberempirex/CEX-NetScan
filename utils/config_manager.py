import json
import os

class ConfigManager:
    def __init__(self, path="config.json"):
        self.path = path
        self.config = self.load()

    def load(self):
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "r") as f:
            return json.load(f)

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.config, f, indent=2)

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save()

    def reset(self, defaults):
        self.config = defaults
        self.save()
