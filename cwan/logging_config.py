import logging
from logging.handlers import RotatingFileHandler
 
from flask import current_app
 
 
def setup_logging(app):
    if not app.debug:
        # Remove the default Flask logger to avoid duplicate logs
        del app.logger.handlers[:]
 
        # Create a file handler which logs even debug messages
        file_handler = RotatingFileHandler(
            app.config["LOG_FILE"], maxBytes=10240, backupCount=10
        )
        file_handler.setLevel(logging.DEBUG)
 
        # Create a console handler with a higher log level
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
 
        # Create formatter and add it to the handlers
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
 
        # Add the handlers to the app's logger
        app.logger.addHandler(file_handler)
        app.logger.addHandler(console_handler)
 
        # Set the log level
        app.logger.setLevel(getattr(logging, app.config["LOGGING_LEVEL"].upper()))
 
        app.logger.info("Logging setup complete")
 
 