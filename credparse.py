def parse(filename):
    parsed_dict = {}
    with open(filename, "r") as file:
        file_lines = file.readlines()
        for line in file_lines:
            split_line = line.split("=")
            key = split_line[0].strip()
            value = split_line[1].strip()
            parsed_dict[key] = value
    return parsed_dict
