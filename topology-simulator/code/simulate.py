#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# clients observe hijacking
# Tor guards get hijacked
# and every AS is a potential adversary
from __future__ import division
from collections import defaultdict
import sys
import json
import time
import hashlib
import argparse

provider_customer_edges_idx = 0
peer_peer_edges_idx = 1
customer_provider_edges_idx = 2

tie_breaker_hash = 0
tie_breaker_not_last_origin = 1
tie_breaker_last_origin = 2

outFile = None

tieBreaker = tie_breaker_hash

allowMultipleNeighborTypesOnASingleLink = False


def parse_args():
    parser = argparse.ArgumentParser()
    # This is a CAIDA AS topology.
    parser.add_argument("-t", "--topology_file",
                        default="as-rel2/20210401.as-rel2.txt")
    # These are the ASes that we are using as vantage points.
    parser.add_argument("-o", "--origins_file",
                        default="./origins.txt")
    # These are the ASNs that we are calculating the resilience for.
    parser.add_argument("-p", "--policies_file",
                        default="./policies.txt")

    parser.add_argument("-b", "--tie_breaker",
                        default="hash")
    parser.add_argument("-O", "--output_file",
                        default="graces_results.txt")
    parser.add_argument("-e", "--early_exit_optimization",
                        default=False, action="store_true")
    return parser.parse_args()


def getAsRels(prefix, asn):

    baseRels = asdict[asn] if (asn in asdict) else [[], [], []]

    providers = baseRels[customer_provider_edges_idx][:]
    peers = baseRels[peer_peer_edges_idx][:]
    customers = baseRels[provider_customer_edges_idx][:]

    policies = []
    if asn in universalPolicies:
        policies.extend(universalPolicies[asn])
    if prefix in prefixPolicies and asn in prefixPolicies[prefix]:
        policies.extend(prefixPolicies[prefix][asn])
    if asn in postPrefixUniversalPolicies:
        policies.extend(postPrefixUniversalPolicies[asn])

    for policy in policies:
        if policy.startswith("EXTRA_PROVIDER@"):
            targetASN = policy.split("@")[1]
            if targetASN in providers:
                # print("Policy: " + policy + " had no effect.")
                pass
            elif not allowMultipleNeighborTypesOnASingleLink and (targetASN in peers or targetASN in customers):
                # print("Policy: " + policy + " ignored because target ASN was already a peer or customer.")
                pass
            else:
                providers.append(targetASN)
        elif policy.startswith("EXTRA_PEER@"):
            targetASN = policy.split("@")[1]
            if targetASN in peers:
                # print("Policy: " + policy + " had no effect.")
                pass
            elif not allowMultipleNeighborTypesOnASingleLink and (targetASN in providers or targetASN in customers):
                # print("Policy: " + policy + " ignored because target ASN was already a provider or customer.")
                pass
            else:
                peers.append(targetASN)
        elif policy.startswith("EXTRA_CUSTOMER@"):
            targetASN = policy.split("@")[1]
            if targetASN in customers:
                # print("Policy: " + policy + " had no effect.")
                pass
            elif not allowMultipleNeighborTypesOnASingleLink and (targetASN in providers or targetASN in peers):
                # print("Policy: " + policy + " ignored because target ASN was already a provider or customer.")
                pass
            else:
                customers.append(targetASN)
        elif policy.startswith("IGNORE_PREVIOUS_NEIGHBORS"):
            providers.clear()
            customers.clear()
            peers.clear()
        elif policy.startswith("USE_NEIGHBORS@"):
            targetASNList = policy.split("@")[1].split(",")

            delta_prov = [_ for _ in targetASNList if _ in providers]
            delta_cust = [_ for _ in targetASNList if _ in customers]
            delta_peer = [_ for _ in targetASNList if _ in peers]

            providers.clear()
            providers.extend(delta_prov)
            customers.clear()
            customers.extend(delta_cust)
            peers.clear()
            peers.extend(delta_peer)

        elif policy.startswith("NO_EXPORT@"):
            targetASN = policy.split("@")[1]
            prev = len(providers) + len(customers) + len(peers)
            if targetASN in providers: providers.remove(targetASN)
            if targetASN in customers: customers.remove(targetASN)
            if targetASN in peers: peers.remove(targetASN)

            newlen = len(providers) + len(customers) + len(peers)
            removed = (prev > newlen)

            if not removed:
                print("Policy: " + policy + " had no effect.")
        elif policy.startswith("NO_EXPORT_PEER"):
            if len(peers) == 0:
                print("Policy: " + policy + " had no effect.")
            peers.clear()

    res = [customers, peers, providers]
    return res


def get_path_origin(path_str):
    return path_str.split(" ")[-1]


def checkNoImportPolicy(policy, possibleAsPath):
    has_no_import_policy = False
    if policy.startswith("NO_IMPORT"):
        splitPolicy = policy.split("#")
        originAS = get_path_origin(possibleAsPath) #possibleAsPath.split(" ")[-1]
        if (len(splitPolicy) == 1) or (originAS == splitPolicy[1]):
            has_no_import_policy = True

    return has_no_import_policy


def hasNoImport(prefix, asn, possibleAsPath):
    if asn in universalPolicies:
        for policy in universalPolicies[asn]:
            if checkNoImportPolicy(policy, possibleAsPath):
                return True
    if prefix in prefixPolicies and asn in prefixPolicies[prefix]:
        for policy in prefixPolicies[prefix][asn]:
            if checkNoImportPolicy(policy, possibleAsPath):
                return True
    return False


def checkIfPrependPolicyAppliesToNeighbor(policy, relationship, neighbor):
    ret_code = 1
    if "@" in policy:
        secondPart = policy.split("@")[1]
        targetASN = secondPart.split("*")[0]
        ret_code = 3 if (targetASN == neighbor) else -1

    elif policy.startswith("PREPEND_CUSTOMER"):
        ret_code = 2 if (relationship == provider_customer_edges_idx) else -1

    elif policy.startswith("PREPEND_PEER"):
        ret_code = 2 if (relationship == peer_peer_edges_idx) else -1

    elif policy.startswith("PREPEND_PROVIDER"):
        ret_code = 2 if (relationship == customer_provider_edges_idx) else -1

    return ret_code


def checkIfPrependPolicyAppliesToOrigin(policy, possibleAsPath):
    if "#" in policy:
        targetOrigin = policy.split("#")[1]
        origin = get_path_origin(possibleAsPath)
        return 2 if (targetOrigin == origin) else -1
    else:
        return 1


def checkIfPrependPolicyApplies(policy, possibleAsPath, relationship, neighbor):
    return (checkIfPrependPolicyAppliesToNeighbor(policy, relationship, neighbor),
            checkIfPrependPolicyAppliesToOrigin(policy, possibleAsPath))


def getPrependCount(policy):
    secondPart = policy.split("*")[1]
    return int(secondPart.split("#")[0])

# This code is complex because we need to make sure that the most specific prepend overrides. This way an origin-specific prepend can override a general prepend.

def getAsPrepend(prefix, asn, possibleAsPath, relationship, neighbor):
    maxPrepend = None
    if asn in universalPolicies:
        for policy in universalPolicies[asn]:
            if not policy.startswith("PREPEND"):
                continue
            applied = checkIfPrependPolicyApplies(policy, possibleAsPath, relationship, neighbor)
            if applied[0] > 0 and applied[1] > 0:
                if (maxPrepend is None) or (applied[0] > maxPrepend[0]) or \
                   ((applied[0] == maxPrepend[0]) and (applied[1] > maxPrepend[1])):
                    maxPrepend = (applied[0], applied[1], getPrependCount(policy))
    if prefix in prefixPolicies and asn in prefixPolicies[prefix]:
        for policy in prefixPolicies[prefix][asn]:
            if not policy.startswith("PREPEND"):
                continue
            applied = checkIfPrependPolicyApplies(policy, possibleAsPath, relationship, neighbor)
            if applied[0] > 0 and applied[1] > 0:
                if (maxPrepend is None) or (applied[0] > maxPrepend[0]) or \
                   ((applied[0] == maxPrepend[0]) and (applied[1] > maxPrepend[1])):
                    maxPrepend = (applied[0], applied[1], getPrependCount(policy))

    if maxPrepend is None:
        return 1
    else:
        return maxPrepend[2]


def addAtIndex(list_of_sets, idx, value):

    list_of_sets.extend([set() for _ in range(idx + 1 - len(list_of_sets))])
    list_of_sets[idx].add(value)


def getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, relationship, neighbor):
    prepend = getAsPrepend(prefix, asn, possibleAsPath, relationship, neighbor)
    asPthInjectionString = (asn + " ") * (prepend - 1)
    return (pathLength + prepend, neighbor + " " + asPthInjectionString + possibleAsPath)


def newASPathBeatsPreviousASPathInTie(newAsPath, previousASPath, lastOrigin, salt):
    global tieBreaker
    prev_origin = get_path_origin(previousASPath)
    new_origin = get_path_origin(newAsPath)
    if tieBreaker == tie_breaker_hash:
        # If we want to change the output of the hash, adjust the salt (also can set it equal to the prefix to include the prefix in the salt if wanted).
        # The hash tiebreak is neighbor-based hashing meaning the values for the ASN names other than the ASN names of the immediate neighbors of the AS breaking the tie are irrelevant.
        return hashlib.md5((salt + previousASPath.split(" ")[1]).encode("utf-8")).hexdigest() < hashlib.md5((salt + newAsPath.split(" ")[1]).encode("utf-8")).hexdigest()

    elif tieBreaker == tie_breaker_last_origin:
        # Break in favor of the last origin. Also prefer old AS paths over new to save cycles.
        return new_origin == lastOrigin and prev_origin != lastOrigin

    elif tieBreaker == tie_breaker_not_last_origin:
        return new_origin != lastOrigin and prev_origin == lastOrigin
    else:
        return False


def entirePrintListInRouteDict(routeDict):
    #return False # To disable the optimization, always return false.
    global printList
    for asn in printList:
        if asn not in routeDict:
            return False
    #print("Return true early break.", file=sys.stderr)
    return True


def stage1(s1_queue, s2_queue, s3_queue, lastOrigin, prefix):
    global usePrintListOptimization
    routeDict = {}
    pathLength = 0
    while pathLength < len(s1_queue):
        if pathLength == 0:
            pass
        if usePrintListOptimization and entirePrintListInRouteDict(routeDict):
            break
        asSet = s1_queue[pathLength]
        for asn, possibleAsPath in asSet:
            if hasNoImport(prefix, asn, possibleAsPath):
                continue
            if asn in routeDict:
                routeDictObject = routeDict[asn]
                if routeDictObject[0] == provider_customer_edges_idx and routeDictObject[1] == pathLength: #tiebreak case
                    # Equal paths case
                    previousASPath = routeDictObject[2]
                    # Comparing MD5 digests of the AS path may not be the best because it causes the route choosen to be a function of the entire AS path not the last hop which is more realistic. Should probably change.
                    # Switch based on tie break setting.
                    if newASPathBeatsPreviousASPathInTie(possibleAsPath, previousASPath, lastOrigin, ""):
                        # if the new route wins the tiebreak, go back and update routeDict
                        routeDict[asn] = (provider_customer_edges_idx, pathLength, possibleAsPath)
                        cpEdges = getAsRels(prefix, asn)[customer_provider_edges_idx]

                        for provider in cpEdges:
                            oldPathLength, oldAsPath = getNewAsPathAndLength(prefix, asn, pathLength, previousASPath, customer_provider_edges_idx, provider)
                            newPathLength, newAsPath = getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, customer_provider_edges_idx, provider)
                            s1_queue[oldPathLength].remove((provider, oldAsPath))
                            addAtIndex(s1_queue, newPathLength, (provider, newAsPath))
                        ppEdges = getAsRels(prefix, asn)[peer_peer_edges_idx]
                        for peer in ppEdges:
                            oldPathLength, oldAsPath = getNewAsPathAndLength(prefix, asn, pathLength, previousASPath, peer_peer_edges_idx, peer)
                            newPathLength, newAsPath = getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, peer_peer_edges_idx, peer)
                            s2_queue[oldPathLength].remove((peer, oldAsPath))
                            addAtIndex(s2_queue, newPathLength, (peer, newAsPath))
                        pcEdges = getAsRels(prefix, asn)[provider_customer_edges_idx]
                        for customer in pcEdges:
                            oldPathLength, oldAsPath = getNewAsPathAndLength(prefix, asn, pathLength, previousASPath, provider_customer_edges_idx, customer)
                            newPathLength, newAsPath = getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, provider_customer_edges_idx, customer)
                            s3_queue[oldPathLength].remove((customer, oldAsPath))
                            addAtIndex(s3_queue, newPathLength, (customer, newAsPath))
            else:
                routeDict[asn] = (provider_customer_edges_idx, pathLength, possibleAsPath)
                asRels = getAsRels(prefix, asn)
                cpEdges = asRels[customer_provider_edges_idx]

                for provider in cpEdges:
                    length, asPath = getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, customer_provider_edges_idx, provider)
                    addAtIndex(s1_queue, length, (provider, asPath))
                ppEdges = asRels[peer_peer_edges_idx]
                for peer in ppEdges:
                    length, asPath = getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, peer_peer_edges_idx, peer)
                    addAtIndex(s2_queue, length, (peer, asPath))
                pcEdges = asRels[provider_customer_edges_idx]
                for customer in pcEdges:
                    length, asPath = getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, provider_customer_edges_idx, customer)
                    addAtIndex(s3_queue, length, (customer, asPath))

        pathLength += 1

    return routeDict



def traverse_path(routeDict, current_queue, next_queue, stage_idx, lastOrigin, prefix):
    global usePrintListOptimization
    pathLength = 0
    while pathLength < len(current_queue):
        if usePrintListOptimization and entirePrintListInRouteDict(routeDict):
            break
        asSet = current_queue[pathLength]
        for asn, possibleAsPath in asSet:
            if hasNoImport(prefix, asn, possibleAsPath):
                continue
            if asn in routeDict:
                routeDictObject = routeDict[asn]
                if routeDictObject[0] == stage_idx and routeDictObject[1] == pathLength:
                    previousASPath = routeDictObject[2]
                    if newASPathBeatsPreviousASPathInTie(possibleAsPath, previousASPath, lastOrigin, ""):
                        routeDict[asn] = (stage_idx, pathLength, possibleAsPath)
                        pcEdges = getAsRels(prefix, asn)[provider_customer_edges_idx]
                        for customer in pcEdges:
                            oldPathLength, oldAsPath = getNewAsPathAndLength(prefix, asn, pathLength, previousASPath, provider_customer_edges_idx, customer)
                            newPathLength, newAsPath = getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, provider_customer_edges_idx, customer)
                            next_queue[oldPathLength].remove((customer, oldAsPath))
                            addAtIndex(next_queue, newPathLength, (customer, newAsPath))
            else:
                routeDict[asn] = (stage_idx, pathLength, possibleAsPath)
                pcEdges = getAsRels(prefix, asn)[provider_customer_edges_idx]
                for customer in pcEdges:
                    length, asPath = getNewAsPathAndLength(prefix, asn, pathLength, possibleAsPath, provider_customer_edges_idx, customer)
                    addAtIndex(next_queue, length, (customer, asPath))
        pathLength += 1

    return routeDict


def load_caida_as_rel(topo_file):

    topo_dict = defaultdict(lambda: [[], [], []])

    # load AS relationships from CAIDA topo file
    # every [provider-customer edges] is a list of ASes that are customers.
    # This should really be thought of as:
    # asdict[asn] = [[customer ASNs],[peers],[providers]]
    # asdict[asn] = [[provider-customer edges],[peer-to-peer edges],[customer-provider edges]]
    for line in open(topo_file):
        if not line.strip().startswith("#"):
            # file format:
            # <provider-as>|<customer-as>|-1|<source> OR <peer-as>|<peer-as>|0|<source>
            # -1: provider-customer; 0: peer-to-peer
            arr = line.strip().split('|')

            asn1, asn2, rel = arr[0], arr[1], int(arr[2])

            if rel == -1: # provider-customer
                topo_dict[asn1][0].append(asn2)
                topo_dict[asn2][2].append(asn1)
            else:   # peer-to-peer
                topo_dict[asn1][1].append(asn2)
                topo_dict[asn2][1].append(asn1)

    return topo_dict


def load_policies(pol_file):

    prefix_pol_dict = defaultdict(lambda: {}) #key: prefix

    for line in open(pol_file):
        if line.strip().startswith("#") or line.strip() == "":
            continue
        split_by_prfx = line.strip().split(">")

        policy_dict = {}
        if len(split_by_prfx) > 1: # policy has prefix and isn't manual override/universal policy
            prefix = split_by_prfx[1]
            policy_dict = prefix_pol_dict[prefix]
        elif line.strip().startswith("!"):
            policy_dict = prefix_pol_dict["POST_PRFX_UNIV"]

        else:
            policy_dict = prefix_pol_dict["UNIV"]

        policy_and_asn = split_by_prfx[0].split(":")
        asn, policy = policy_and_asn[0], policy_and_asn[1]
        if asn.startswith("!"):
            asn = asn[1:]
        if asn not in policy_dict:
            policy_dict[asn] = []
        policy_dict[asn].append(policy)

    uni_dict = prefix_pol_dict.pop("UNIV", {})
    post_prfx_univ_dict = prefix_pol_dict.pop("POST_PRFX_UNIV", {})

    return (uni_dict, prefix_pol_dict, post_prfx_univ_dict)


def getRouteDict(prefix, originatingASes):
    lastOrigin = originatingASes[-1]
    # routedict key: ASN number value: (connection_idx [0, 1, or 2], path length, path)
    s1AsPathLengthList = [set([(_, _) for _ in originatingASes])]
    s2AsPathLengthList = []
    s3AsPathLengthList = []
    stage1dict = stage1(s1AsPathLengthList, s2AsPathLengthList, s3AsPathLengthList, lastOrigin, prefix)
    stage2dict = traverse_path(stage1dict, s2AsPathLengthList, s3AsPathLengthList, peer_peer_edges_idx, lastOrigin, prefix)
    stage3dict = traverse_path(stage2dict, s3AsPathLengthList, s3AsPathLengthList, customer_provider_edges_idx, lastOrigin, prefix)

    return stage3dict


def main(args):
    global asdict, total_as, universalPolicies, postPrefixUniversalPolicies, prefixPolicies, tieBreaker, printList, usePrintListOptimization
    printList = ["salt_lake", "denver", "ohio_1", "ohio_2", "oregon_1", "oregon_2", "frankfurt_1", "frankfurt_2", "singapore_1", "tokyo_1", "paris_1", "london_1", "88"] # "sbasoregonnode",  "isi01", 
    if args.early_exit_optimization:
        usePrintListOptimization = True
    else:
        usePrintListOptimization = False

    if args.tie_breaker != "hash":
        if args.tie_breaker == "last_origin":
            tieBreaker = tie_breaker_last_origin
            print(f"Using tie break mode {args.tie_breaker}.")
        elif args.tie_breaker == "not_last_origin":
            tieBreaker = tie_breaker_not_last_origin
            print(f"Using tie break mode {args.tie_breaker}.")
        else:
            print("Unknown tie break setting: {}".format(args.tie_breaker), file=sys.stderr)
            exit()

    asdict = load_caida_as_rel(args.topology_file)

    # Populate the origin dictionary with 0 resilience for every node.
    # originSet will eventually become the resiliance of every origin node.
    total_as = len(asdict)
    print("ASes found in topology: {}".format(total_as))
    print("Origins file: {}".format(args.origins_file))

    universalPolicies, prefixPolicies, postPrefixUniversalPolicies = load_policies(args.policies_file)

    start = time.time()

    # write results to file
    f = open(args.output_file, "w")

    for line in open(args.origins_file):
        originLineSplit = line.strip().split(":")
        prefix = originLineSplit[0]
        originatingASesText = originLineSplit[1]
        # originList.append([prefix, [asnText.strip() for asnText in originatingASesText.split(",")]])
        # prefix = originData[0]
        data = [asnText.strip() for asnText in originatingASesText.split(",")]
        lastOrigin = data[-1]
        #data = originData[1]
        print("Prefix: {}".format(prefix))
        print("Last Origin: {}".format(lastOrigin))
        # lines with duplicate AS as origins in the list are dropped
        if len(set(data)) < len(data):
            print("Duplicate origin for prefix (skipping): {}".format(prefix))
            continue

        # in effect: for this prefix, which AS in [data] will be chosen for every other AS?
        routeDict = getRouteDict(prefix, data)
        effectDict = {}
        for origin in data:
            effectDict[origin] = set()

        for asn in routeDict:
            asPath = routeDict[asn][2]
            for possibleOrigin in effectDict:
                if asPath.endswith(possibleOrigin):
                    effectDict[possibleOrigin].add(asn)
        # printList = ["1", "2", "3", "4", "5", "11", "12", "13", "14", "144", "133", "140", "130"]
        for asn in printList:
            if asn in routeDict:
                print(json.dumps(routeDict[asn]))
        # Origin influences have no meaning if we use early exit on the print list.
        if not usePrintListOptimization:
            # orgn_influences = [(asn, len(effectDict[asn])) for asn in effectDict]
            orgn_influences = [(asn, effectDict[asn]) for asn in effectDict]
            file_line = "|".join([f'{asn_infl[0]}:{asn_infl[1]}' for asn_infl in orgn_influences])
            f.write(file_line)
            f.write("\n")
            # print(json.dumps(orgn_influences))

    f.close()
    end = time.time()
    print("Run time in seconds: {}".format(end - start))
    # note that the output is keyed by client.
    # it is a 2d map. The first level is the client ASN. Within the client AS we have a map


if __name__ == '__main__':
    main(parse_args())
