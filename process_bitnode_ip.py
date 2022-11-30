import requests, json, os, subprocess

save_file = 'data/bitnodes_1669409807.json'
f = open(save_file, "r")
contents = json.load(f)
print("Load from {}".format(save_file))
f.close()

ips = list(contents['nodes'].keys())

f = open(save_file[:-5] + ".ip", "w")
f.write('begin\n')
f.write('verbose\n')
for ip in ips:
    f.write(ip + "\n")
f.write('end\n')
f.close()
print("Saved ip addresses to {}".format(save_file[:-5] + ".ip"))

cmd = ['netcat', 'whois.cymru.com', '43']

infile = open(save_file[:-5] + ".ip", "r")
outfile = open(save_file[:-5] + ".processed", "w")
errfile = open('/dev/null', "a")
p = subprocess.Popen(cmd, stdin=infile, stdout=outfile, stderr=outfile)
p.wait()
print("Saved the corresponding ASN and prefix information to {}".format(save_file[:-5] + ".processed"))