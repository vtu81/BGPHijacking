# topology-simulator
Topology simulations based on modeling on quicksand.

# Usenix 22 Artifact Evaluation
At a high level, the simulation code can be evaluated by running ```code/simulate.py``` with the specified input files in ```data/```. After the simulation result for the RPKI and non-RPKI simulations can be processed in to the CDF graphs in the paper using ```code/plot_artifact_result.py```. Below is a description/interpretation of the input and output formats, a description of how the input files were generated, and commands to rerun the simulations given a scaled-down version of the input files.

## An overview of simulate.py
simulate.py performs an interdomain Internet topology simulation based on the "routing tree" algorithm discussed in "Modeling on quicksand: dealing with the scarcity of ground truth in interdomain routing data" (https://dl.acm.org/doi/10.1145/2096149.2096155). Running ```python3 simulate.py -h``` (from the code directory; all python commands are intended to be executed from the code directory) gives the help output showing the various input file flags:

```
usage: simulate.py [-h] [-t TOPOLOGY_FILE] [-o ORIGINS_FILE] [-p POLICIES_FILE] [-b TIE_BREAKER] [-O OUTPUT_FILE] [-e]

optional arguments:
  -h, --help            show this help message and exit
  -t TOPOLOGY_FILE, --topology_file TOPOLOGY_FILE
  -o ORIGINS_FILE, --origins_file ORIGINS_FILE
  -p POLICIES_FILE, --policies_file POLICIES_FILE
  -b TIE_BREAKER, --tie_breaker TIE_BREAKER
  -O OUTPUT_FILE, --output_file OUTPUT_FILE
  -e, --early_exit_optimization
```

This flags specify all input files to the simulation framework. Below they are explained in order.

### TOPOLOGY_FILE
This is a CAIDA AS-relationship dataset topology file. It contains an AS-level Internet topology graph inferred from public BGP data. These are publicly available and are released monthly by CAIDA based on RIB files from public route collectors. The topology file from 2021-04-01 is included in the ```data/topo``` directory for convenience, but other files can be downloaded at https://www.caida.org/catalog/datasets/as-relationships/.

### ORIGINS_FILE
Given the Internet topology, the simulator must simulate BGP announcements over the topology. The origins file specifies which ASes should announce a prefix that is simulated in each topology simulation. Every line of the origins file corresponds to a distinct simulation. The origins file format is:

```
<prefix_name>:<comma separated list of origin ASes>
```

For example, the first line of the origins file ```data/origins/origins-sbas-k100adv.txt``` is 

```
victim_prefix:amsterdam01,seattle01,isi01,63405
```

which causes the simulator to run a simulation for a prefix named ```victim_prefix``` that is originated by the ASes amsterdam01, seattle01, isi01, and 63405. This will trigger a full Internet routing simulation for this prefix presuming it is announced by these ASes. The simulator will find the AS-level route used by every AS in the CAIDA topology and determine which of the four origin ASes that route will send its traffic to. In this setup, amsterdam01, seattle01, and isi01 are SBAS nodes and 63405 is a randomly chosen AS on the Internet that is serving as an adversary in this simulation. By convention, we use the last AS in the origin line to signify the adversary being simulated. The script that process the simulation output make this assumption, but the simulator does not treat the adversary differently than the legitimate origins in the simulations.

Valid origins files are in the ```data/origins/``` directory. ```data/origins/origins-sbas-k100adv.txt``` contains a 10% subset of the random sample used in the paper. This is a rather large simulation. Based the speed of the simulation on a benchmark we performed on a personal computer, this file will take about 60 hours to run. We also included an abridged version ```data/origins/origins-sbas-k100adv.800.txt``` that only includes the first 800 simulations and runs in about 25 min.

The file ```origins-sbas-k100adv.txt``` has two parts. The first part is for simulations of different number of SBAS PoPs as victim's with a random sample of 100 ASes on the Internet as adversaries. The second part uses random prefixes (which we modeled on BGP announcements observed from public route collectors) on the Internet as victims and the same sample of 100 ASes as adversaries. These two types of simulations are used to produce the no SBAS (i.e., random internet prefix) and 3, 4, 5, 6 node SBAS scenarios. 

### POLICIES_FILE

In addition to running a conventional routing simulation, the simulator has the option of loading a policy file that can augment the routing behavior of select ASes on the Internet. A large number of scenarios can be encoded into the policies file, but we specifically used it for two functions: 1) adding the SBAS nodes to the CAIDA topology (the SBAS nodes operate out of the PEERING testbed which is not well represented in the CAIDA topology given that it is a research testbed that uses AS-path poisoning and reuses its ASN between multiple PoPs) and 2) optionally instructing adversary ASes to prepend their announcements as is required to evade ROV enforcement. The policies file also contains some data about the announcement patterns of real prefixes seen in BGP RIBs used for the simulations in the no SBAS case.

We include both the standard non-ROV and ROV versions of the policies file in ```data/policies/policies-sbas-victims.txt``` and ```data/policies/policies-sbas-victims-rpki.txt``` respectively. Changing between these two versions of the policies file can determine whether the standard or ROV version of the simulations are being run.

Additionally, the PEERING-related part of the policy file can be regenerated from the PEERING Testbed peers list (stored in ```data/peering/peers.csv```) using the script ```code/peering_list_to_policies_peering.py``` that takes the ```peers.csv``` file as the first command line arg and outputs PEERING-related policies to stdout (although regeneration is not necessary as the peering policies are already included in files in ```data/policies/```)

### TIE_BREAKER
This changes the tie break behavior of the simulation when all Gao-Rexford conditions tie. The default tie break was used in the paper to this flag does not need to be set.

### OUTPUT_FILE
This is the location for the output of the simulation. The simulation produces two output streams: a full debug stream to stdout and a concise output file specifically formatted for these analysis tasks that is written to OUTPUT_FILE. The format of OUTPUT_FILE is:

```
<origin>:<number of ASes in the Internet topology that route data to that origin>,...
```

(note that the prefix name is not output as the analysis script does not depend on it and this saves space on large simulation runs)


For example, the fist line of output from the SBAS simulations is

```amsterdam01:17641,seattle01:3635,isi01:29288,63405:21854```

This line can be read as the 17641 ASes on the Internet routed data to the amsterdam01 node in this simulation, 3635 ASes routed to seattle01, etc... The final part of the line states that 21854 ASes routed to the simulated adversary AS 63405. To give this line context, of the 72,418 ASes modeled in the Internet topology, 50,564 of them (70%) routed to one of the SBAS origins and 21,854
of them routed to the adversary AS 63405. This, by the definition in the paper, against this adversary, this particular collection of SBAS nodes has a resilience of 70%.

For context, if we look at the same line in the ROV simulation (which weakens the power of the adversary as they must now evade ROV/RPKI), the SBAS nodes are able to route data from an even larger fraction of the Internet:

```amsterdam01:23022,seattle01:5094,isi01:33103,63405:11199```

Here SBAS nodes attract traffic from 61,219 ASes or 85% of the ASes in the topology. Thus, assuming ROV adoption, against this specific adversary this collection of SBAS nodes has a resilience of 85%. Because the resilience of SBAS against a single adversary varies based on adversary locations, we compile all the simulation results into a CDF that graphically represents the resilience against the entire set of adversaries.

### early_exit_optimization
This is an optimization available when this script is used in other contexts. IT WILL CORRUPT THE OUTPUT REQUIRED FOR THE SBAS SIMULATION. Do not add this flag.

## Running simulate.py

simulate.py primarily depends on python3. We were able to run it on a clean Ubuntu 22.04 VM with no ```apt``` or ```pip``` commands as it only depends on already-installed standard libraries.

Before running the simulator, we recommend you make a directory called ```output/``` in the repo that will be ignored by git (based on the repos ```.gitignore```). From the base of the repo run:

```mkdir output```

Then cd to the code dir:

```cd code```

Below is an example run command that can be executed from the ```code/``` directory that points to all the default input files contained in the data directory and generates two output files in the ```output``` directory: one is a file with the concise simulation output (```../output/simul800-output.txt```) and the other is the full simulation debug output (```../output/simul800-status-output.txt```). This command also sends the status output to stdout for convenience. (note the -u flag on the python command that allows for status output during the execution of the simulation by avoiding buffering)

```python3 -u simulate.py -t ../data/topo/20210401.as-rel2.txt -o ../data/origins/origins-sbas-k100adv.800.txt -p ../data/policies/policies-sbas-victims.txt -O ../output/simul800-output.txt | tee ../output/simul800-status-output.txt```

This simulation took us 26 minutes on a personal machine with a recent generation CPU. This version of the script is not multi-threaded so it will not benefit from being run on a cluster/HPC node. Once the above simulation command runs, it will generate the standard non-RPKI output files.

Below is a variant of the command that loads the RPKI policies file to run the RPKI simulations and writes the RPKI/ROV output files:

```python3 -u simulate.py -t ../data/topo/20210401.as-rel2.txt -o ../data/origins/origins-sbas-k100adv.800.txt -p ../data/policies/policies-sbas-victims-rpki.txt -O ../output/simul800-output-rpki.txt | tee ../output/simul800-status-output-rpki.txt```

Post processing requires both the standard and RPKI results to regenerate figures 8 and 9 from the paper. The RPKI results should run at a comparable speed to the standard simulations.

## Running plot_artifact_result.py

plot_artifact_result.py has several dependencies that do not come out of the box with python. Crucially, it depends on Latex and some particular latex style files that matplotlib requires. On our Ubuntu 22.04 VM we had to install the following pip3 and apt dependencies with these commands.

```
pip3 install matplotlib
pip3 install seaborn
pip3 install latex
apt install texlive texlive-latex-extra texlive-fonts-recommended dvipng cm-super
```

After these dependencies are met, plot_artifact_result.py should be able to take both the standard and ROV output files and generate CDFs like those in the paper figures 8 and 9. It takes the files as positional arguments with the standard output first and the ROV output second. Below is a command that can be run from the ```code/``` directory and uses the output file names from this document.

```python3 plot_artifact_result.py ../output/simul800-output.txt ../output/simul800-output-rpki.txt```

plot_artifact_result.py produces an output file named ```sbas_artifact_cdf.png``` in the directory where it is run (in this case ```code/```). This PNG file shows a CDF that summarizes the results of the simulation run with the simulator. This is the same format of CDF that is displayed in figures 8 and 9 in the paper. Node that particularly when the 800-line input files are used, this CDF is much less smooth than the ones in the paper but that is because the paper CDFs were generated with significantly more simulations. The trends in the paper are still visible where SBAS outperforms no-SBAS, additional nodes improves resilience, and ROV adoption additionally improves resilience.

