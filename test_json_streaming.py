import ijson

def validate_json(file_path):
    try:
        with open(file_path, "rb") as file:
            events = ijson.parse(file)

            for _ in events:
                pass

        return True

    except (ijson.JSONError, OSError):
        return False

print(validate_json("samples/json_tests/empty.json"))
