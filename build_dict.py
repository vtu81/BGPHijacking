import json, os

save_file = 'data/bitnodes_1669409807.processed'
f = open(save_file, "r")
print("Load from {}".format(save_file))

b_asn = dict()
b_ip_prefix = dict()
asn_to_ip_prefix = dict()
ip_prefix_to_asn = dict()

for line in f:
    if line[:5] == "Error" or line[:5] == "Bulk ": continue
    line = line.split('|')
    
    asn = line[0].strip()
    ip_prefix = line[2].strip()
    
    if asn in b_asn.keys(): b_asn[asn] += 1
    else: b_asn[asn] = 1
    
    if ip_prefix in b_ip_prefix.keys(): b_ip_prefix[ip_prefix] += 1
    else: b_ip_prefix[ip_prefix] = 1
    
    
    if ip_prefix not in ip_prefix_to_asn.keys(): ip_prefix_to_asn[ip_prefix] = asn
    elif asn != ip_prefix_to_asn[ip_prefix]: print("Conflict! asn = {} while previous record is {} (ip prefix {})".format(asn, ip_prefix_to_asn[ip_prefix], ip_prefix))
    
    if asn == ip_prefix_to_asn[ip_prefix]:
        if asn in asn_to_ip_prefix.keys():
            if ip_prefix not in asn_to_ip_prefix[asn]: asn_to_ip_prefix[asn].append(ip_prefix)
        else: asn_to_ip_prefix[asn] = [ip_prefix]
    elif asn not in asn_to_ip_prefix.keys(): asn_to_ip_prefix[asn] = []
    
    
f.close()

print("Total ASes:", len(b_asn.keys()))
print("Total ip prefixes:", len(b_ip_prefix.keys()))

save_file = os.path.join("data", "b_asn.json")
f = open(save_file, "w")
json.dump(b_asn, f)
print("Saved dict b_asn to {}".format(save_file))

save_file = os.path.join("data", "b_ip_prefix.json")
f = open(save_file, "w")
json.dump(b_ip_prefix, f)
print("Saved dict b_ip_prefix to {}".format(save_file))

save_file = os.path.join("data", "asn_to_ip_prefix.json")
f = open(save_file, "w")
json.dump(asn_to_ip_prefix, f)
print("Saved dict asn_to_ip_prefix to {}".format(save_file))

save_file = os.path.join("data", "ip_prefix_to_asn.json")
f = open(save_file, "w")
json.dump(ip_prefix_to_asn, f)
print("Saved dict ip_prefix_to_asn to {}".format(save_file))