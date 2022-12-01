import json, os, config
import argparse

# Load bitnodes counting dicts
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

save_file = os.path.join("data", "ip_prefix_to_asn.json")
f = open(save_file, "r")
ip_prefix_to_asn = json.load(f)
print("Load dict ip_prefix_to_asn from {}".format(save_file))
f.close()

# Load initial scores of all prefixes
save_file = os.path.join("data", "prefix_score.txt")
f_score = open(save_file, "r")
print("Load initial scores from {}".format(save_file))

scores_dict = dict()
for line in f_score:
    terms = line.split(':')
    scores_dict[terms[0]] = int(terms[1])
f_score.close()

# Load followers of adversary AS for each victim AS
save_file = os.path.join("data", "simul_output.txt")
f = open(save_file, "r")
print("Load simulation results from {}".format(save_file))

followers_dict = dict()
for line in f:
    terms = line.split('|')
    assert len(terms) == 2
    
    victim_asn = terms[0].split(':')[0] # assuming the first term is the victim AS
    adv_asn = terms[-1].split(':')[0] # assuming the last term is the adversarial AS
    
    t = terms[-1]
    _, followers = t.split(':')
    followers = followers.replace(' ', '').replace("'", '').replace('{', '').replace('}', '').split(',')
    followers = [f for f in followers]
    
    followers_dict[victim_asn] = followers
f.close()


def add_prefix(selected_prefixes, selected_prefixes_score, new_prefix):
    """get the updated score of `selected_prefixes` \cup \{`new_prefix`\}, given the precalculated `selected_prefixes_score`
    selected_prefixes: list of string
    selected_prefixes_score: int
    new_prefix: string
    """
    # If the AS of `new_prefix` already exists in the followers of `selected_prefixes`,
    # then those connections are already recorded before and we don't need to count them twice.
    
    new_selected_prefixes_score = selected_prefixes_score
    new_asn = ip_prefix_to_asn[new_prefix]
    selected_asn = []
    for pf in selected_prefixes:
        asn = ip_prefix_to_asn[pf]
        selected_asn.append(asn)
    for follower in followers_dict[new_asn]:
        if follower not in selected_asn and follower in b_asn.keys():
            new_selected_prefixes_score += b_ip_prefix[new_prefix] * b_asn[follower]
    return new_selected_prefixes_score

def choose_prefixes(initial_scores_dict, k):
    """Choose the best `k` ip prefixes to hijack to capture the most connections
    """
    selected_prefixes = []
    prefixes = list(initial_scores_dict.keys())
    scores = list(initial_scores_dict.values())
    
    # Sort the ip prefixes by their initial score in decreasing order
    # prefixes.sort(reverse=True, key=lambda x:initial_scores_dict[x])
    # scores = [initial_scores_dict[i] for i in prefixes]
    prefixes = [x for _, x in sorted(zip(scores, prefixes), reverse=True)]
    scores.sort(reverse=True)
    
    # First select the ip prefix with the highest
    selected_prefixes.append(prefixes[0])
    selected_prefixes_score = scores[0]
    prefixes.pop(0)
    scores.pop(0)
    
    for i in range(1, k):
        while len(selected_prefixes) < i + 1:
            new_prefix = prefixes[0]
            new_selected_prefixes_score = add_prefix(selected_prefixes, selected_prefixes_score, new_prefix)
            increment = new_selected_prefixes_score - selected_prefixes_score
            scores[0] = increment # update the top score
            
            if scores[0] > scores[1]:
                selected_prefixes.append(new_prefix)
                selected_prefixes_score = new_selected_prefixes_score
                prefixes.pop(0)
                scores.pop(0)
            else:
                prefixes = [x for _, x in sorted(zip(scores, prefixes), reverse=True)]
                scores.sort(reverse=True)
    
    print("Selected prefixes:", selected_prefixes)
    print("Captured connections num:", selected_prefixes_score)
    return selected_prefixes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', type=int,  required=False)
    args = parser.parse_args()
    
    choose_prefixes(initial_scores_dict=scores_dict, k=args.k)

if __name__ == '__main__':
    main()