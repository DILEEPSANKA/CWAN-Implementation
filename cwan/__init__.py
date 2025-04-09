from flask import Flask
from pymongo import MongoClient

# from cwan.logging_config import setup_logging
from cwan.logging_config import setup_logging

# from .context_processors import inject_common_variables
from cwan.context_processors import inject_common_variables

# from .extensions import init_extensions
# from .extensions.extension_manager import ExtensionManager
from cwan.extensions.extension_manager import ExtensionManager


def create_app():
    app = Flask(__name__)
    app.config.from_object("cwan.config.Config")

    client = MongoClient(app.config["MONGO_URI"])
    app.db = client[app.config["MONGO_DBNAME"]]
    

    setup_logging(app)

    app.before_request(inject_common_variables)
    with app.app_context():
        # from . import routes
        from . import routes
        

        extension_manager = ExtensionManager(app)
        extension_manager.load_extensions()
        # init_extensions(app)
        return app


