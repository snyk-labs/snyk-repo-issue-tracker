from os import scandir



for entry in scandir('cache/org'):
        if not entry.name.startswith('.') and entry.is_dir():
            print(entry.name)