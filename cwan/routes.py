import json

from flask import current_app as app
from flask import render_template,g


def load_config(collection_name, page_name=None):
    return app.db[collection_name].find_one({"name": page_name})

# @app.route("/")
# def home():
#     g.structures = load_config("structures", "home")
#     g.content = load_config("content", "home")
#     return render_template(
#         "home.html"
#     )

# @app.route("/sample")
# def sample():
#     structures = load_config("structures", "home")
#     content = load_config("content", "home")
#     return render_template(
#         "home.html",
#         title=content["title"],
#         body=content["content"],
#         header={
#             "logo": "https://exafluence.com/images/exflogoW.png",
#             "title": "Sample Page",
#         },
#         structures=structures,
#     )
