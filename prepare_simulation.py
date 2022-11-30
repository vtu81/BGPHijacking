import json, os, config

save_file = os.path.join("data", "b_asn.json")
f = open(save_file, "r")
b_asn = json.load(f)
print("Load dict b_asn from {}".format(save_file))
f.close()

save_file = os.path.join("data", "b_ip_prefix.json")
f = open(save_file, "r")
b_ip_prefix = json.load(f)
print(len(b_ip_prefix.keys()))
print("Load dict b_ip_prefix from {}".format(save_file))
f.close()

save_file = os.path.join("data", "asn_to_ip_prefix.json")
f = open(save_file, "r")
asn_to_ip_prefix = json.load(f)
print("Load dict asn_to_ip_prefix from {}".format(save_file))
f.close()


save_file = os.path.join("topology-simulator/data/origins", "origins.txt")
f = open(save_file, "w")
for asn in b_asn:
    f.write("victim_prefix:{},{}".format(asn, config.adv_ASN))
    f.write("\n")
print("Saved to {}".format(save_file))
f.close()