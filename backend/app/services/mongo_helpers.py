NO_ID = {"_id": 0}


def strip_mongo_id(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc
