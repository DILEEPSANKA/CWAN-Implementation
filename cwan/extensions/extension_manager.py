import importlib
import inspect
import os
import sys

from flask import current_app
from jinja2 import ChoiceLoader, FileSystemLoader

# from cwan.extensions.base_extension import BaseExtension
from cwan.extensions.base_extension import BaseExtension
# current_dir = os.path.dirname(os.path.abspath(__file__))

# # Assuming cwanext is located outside of cwan
# project_root = os.path.dirname(os.path.dirname(current_dir))
# cwanext_dir = os.path.join(project_root, 'cwanext')
# # Add cwanext parent directory to Python path if not already added
# if cwanext_dir not in sys.path:
#     sys.path.insert(0, cwanext_dir)

class ExtensionManager:
    def __init__(self, app):
        self.app = app
        self.extensions = []

    def load_extensions(self):
        extension_names = self.app.config.get("EXTENSIONS", [])
        current_app.logger.info(f"Loading extensions: {extension_names}")
        for extension_name in extension_names:
            if extension_name:
                self.load_extension(f"{self.app.config.get('EXTENSION_FOLDER')}.{extension_name}")

    def load_extension(self, extension_name):
        try:
            module = importlib.import_module(extension_name)
            print(module)
            extension_class = self.find_extension_class(module)
            if extension_class:
                extension_instance = module.Extension(self.app)
                extension_instance.register_routes()
                self.app.template_context_processors[None].append(
                    extension_instance.extend_template_context
                )
                self.app.register_blueprint(extension_instance.bp)
                self.extensions.append(extension_instance)
                self.register_template_loader(extension_name)
                current_app.logger.info(f"Loaded extension {extension_name}")
            else:
                current_app.logger.error(
                    f"Failed to load extension {extension_name}: No Extension class found"
                )
        except ImportError as e:
            current_app.logger.error(f"Failed to load extension {extension_name}: {e}")

    def find_extension_class(self, module):
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseExtension) and obj is not BaseExtension:
                return obj
        return None

    def register_template_loader(self, plugin_name):
        module = importlib.import_module(plugin_name)
        template_path = module.__path__[0] + "/templates"
        current_loader = self.app.jinja_loader
        self.app.jinja_loader = ChoiceLoader(
            [
                FileSystemLoader(template_path),
                current_loader,
            ]
        )
