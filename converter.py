import json


with open('input.txt', 'r') as file:
    lines = file.readlines()

results = []

for line in lines:

    stripped_line = line.strip()


    result_entry = {
        "inputField": stripped_line,
        "category": "Java" #allowed variables: "SQL" , "Java", "HTML"
    }

    results.append(result_entry)

with open('results.json', 'w') as json_file:
    json.dump(results, json_file, indent=4, ensure_ascii=False)

print("Payloads written to results.json.")
