import requests, json, os

r = requests.get("https://bitnodes.io/api/v1/snapshots/latest/")
contents = json.loads(r.text)
print(contents.keys())
print("Total bitcoin nodes:", contents['total_nodes'])

if not os.path.exists("data"):
    os.mkdir("data")

save_file = os.path.join("data", "bitnodes_{}.json".format(contents['timestamp']))
f = open(save_file, "w")
json.dump(contents, f)
print("Saved bitnodes information to {}".format(save_file))