import os

ALLOWED_EXTENSIONS = (
    ".js",
    ".env",
    ".json",
    ".yaml",
    ".yml",
    ".config"
)

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    "venv",
    ".venv"
}

def find_files(base_path):
    target_files = []

    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for file in files:
            if file.endswith(ALLOWED_EXTENSIONS):
                full_path = os.path.join(root, file)
                target_files.append(full_path)

    return target_files
