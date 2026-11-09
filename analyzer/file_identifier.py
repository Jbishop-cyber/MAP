import os
import mimetypes

def identify_file(file_path):
    if not os.path.exists(file_path):
        return {"error": "File does not exist"}
    
    if not os.path.isfile(file_path):
        return {"error": "Path is not a file"}
    
    filename = os.path.basename(file_path)
    extension = os.path.splitext(filename)[1]
    file_size = os.path.getsize(file_path)

    mime_type, encoding = mimetypes.guess_type(file_path)

    return {
        "filename": filename,
        "extension": extension,
        "file_size": file_size,
        "mime_type": mime_type or "Unknown"
    }