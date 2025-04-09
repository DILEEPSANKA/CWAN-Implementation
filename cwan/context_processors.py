from flask import current_app as app
from flask import g


def inject_common_variables():
    # header_doc = app.db["content"].find_one({"name": "header"})
    # g.header_content = header_doc["content"]
    # g.header_design = header_doc["design"]
    return
