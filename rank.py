import json, os, config

save_file = os.path.join("data", "b_asn.json")
f = open(save_file, "r")
b_asn = json.load(f)
print("Load dict b_asn from {}".format(save_file))
f.close()

save_file = os.path.join("data", "b_ip_prefix.json")
f = open(save_file, "r")
b_ip_prefix = json.load(f)
print("Load dict b_ip_prefix from {}".format(save_file))
f.close()

save_file = os.path.join("data", "asn_to_ip_prefix.json")
f = open(save_file, "r")
asn_to_ip_prefix = json.load(f)
print("Load dict asn_to_ip_prefix from {}".format(save_file))
f.close()

save_file = os.path.join("data", "simul_output.txt")
f = open(save_file, "r")
print("Load simulation results from {}".format(save_file))

save_file = os.path.join("data", "prefix_score.txt")
f_score = open(save_file, "w")

for line in f:
    terms = line.split('|')
    assert len(terms) == 2
    effectDict = dict()
    for t in terms:
        asn, followers = t.split(':')
        followers = followers.replace(' ', '').replace("'", '').replace('{', '').replace('}', '').split(',')
        followers = [f for f in followers]
        # print("{} ASes are gonna follow AS {}".format(len(followers), asn))
        effectDict[asn] = followers
    victim_asn = terms[0].split(':')[0] # assuming the first term is the victim AS
    adv_asn = terms[-1].split(':')[0] # assuming the last term is the adversarial AS
    
    num_following_bitnodes = 0
    for follower in effectDict[adv_asn]:
        if follower in b_asn.keys(): num_following_bitnodes += b_asn[follower]
    # print("{} bitnodes will follow the adv AS {}".format(num_following_bitnodes, adv_asn))
    
    for ip_prefix in asn_to_ip_prefix[victim_asn]:
        num_victim_bitnodes = b_ip_prefix[ip_prefix]
        num_captured_connections = num_victim_bitnodes * num_following_bitnodes
        f_score.write("{}:{}\n".format(ip_prefix, num_captured_connections))

f_score.close()
print("Saved to {}".format(save_file))
f.close()

