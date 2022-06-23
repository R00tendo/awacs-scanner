def read_file(filename):
    with open(filename, "r") as file:
        lines = filename.read_lines
    return lines