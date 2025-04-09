from flask import Blueprint


class BaseExtension:
    def __init__(self, app):
        self.app = app
        self.bp = Blueprint(
            self.__class__.__name__.lower(), __name__, template_folder="templates"
        )

    def register_routes(self):
        raise NotImplementedError(
            "Each extension must implement the 'register_routes' method."
        )

    def extend_template_context(self):
        return {}

    def overwrite_route(self, route, view_func):
        if route in self.app.view_functions:
            self.app.view_functions[route] = view_func
        else:
            self.bp.add_url_rule(route, view_func=view_func)
