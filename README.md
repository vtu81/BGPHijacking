# BGPHijacking

Prepare data by running:
```
python collect_bitnode_ip.py
python process_bitnode_ip.py
python process_bitnode_ip.py
python build_dict.py
python prepare_simulation.py

cd topology-simulator
python -u code/simulate.py -t data/topo/20210401.as-rel2.txt -o data/origins/origins.txt -p data/policies/policies-empty.txt -O ../data/simul_output.txt

cd ..
python rank.py
```

To launch the main searching process, run:
```
python main.py -k=5
```