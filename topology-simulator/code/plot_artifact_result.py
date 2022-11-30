import matplotlib
matplotlib.use('agg')
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import warnings
import sys

warnings.filterwarnings("ignore", category=UserWarning)
matplotlib.rcParams.update({
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["computer modern roman"]
})

IMG_RES = 800


def autolabel(rects, ax, labels):
    """
    Attach a text label above each bar displaying its height
    """
    for rect_idx in range(len(rects)):
        rect = rects[rect_idx]
        height = rect.get_height()
        lbl = round(labels[rect_idx], 1)
        ax.text(rect.get_x() - rect.get_width()/3., 1.015*height,
                r'\textbf{'+str(lbl) + r'}',
                fontsize=26,
                fontweight='bold',
                ha='center', va='bottom')


def read_and_split(f_nm):
    lines = []
    if isinstance(f_nm, list):
        lines = []
        for f in f_nm:
            lines.extend(open(f_nm, "r").read().splitlines())
    else:
        lines.extend(open(f_nm, "r").read().splitlines())
    return [_.split(",") for _ in lines]


def get_res_to_adv(ls):
    d = {}
    for l in ls:
        adv_as, adv_res = l.split(",")[-1].split(":")
        nodes = [_.split(":") for _ in l.split(",")[:-1]]
        nd_name = "_".join([_[0] for _ in nodes])
        res = sum([int(_[1]) for _ in nodes])
        res_val = res / (res + int(adv_res))
        if nd_name in d:
            d[nd_name].append(res_val)
        else:
            d[nd_name] = [res_val]
    return d


def plot_compare_distribution(sbas_sim_f, sbas_rov_sim_f):

    # ping_client_file_path = "/home/gcimaszewski/cos432/topology-simulator/sbas_artifact_k100.txt"
    ping_client_file_path = sbas_sim_f
    ping_client_lines = []
    with open(ping_client_file_path) as ping_simul_f:
        for line in ping_simul_f:
            try:
                #simul_res = line.strip()[:-1].split(";")[1]
                simul_res = line.strip()
                ping_client_lines.append(simul_res)
            except:
                print(f"Error on line: {line}")
                raise
            # adv_res = simul_res[-1]

    sbas_rov_file_path = sbas_rov_sim_f
    # sbas_rov_file_path = "sbas-artifact-k100-rpki.txt"
    sbas_rov_lines = []
    with open(sbas_rov_file_path) as rov_simul_f:
        for line in rov_simul_f:
            #simul_res = line.strip()[:-1].split(";")[1]
            simul_res = line.strip()
            sbas_rov_lines.append(simul_res)

    ping_client_res = get_res_to_adv(ping_client_lines)
    sbas_rov_res = get_res_to_adv(sbas_rov_lines)

    fig, (ax, ax_rov) = plt.subplots(ncols=2, sharey=True, figsize=(15.8, 4.8))

    sbas_3node = ping_client_res.pop("amsterdam01_seattle01_isi01")
    sbas_4node = ping_client_res.pop("amsterdam01_seattle01_isi01_grnet01")
    sbas_5node = ping_client_res.pop("amsterdam01_seattle01_isi01_grnet01_uw01")
    sbas_6node = ping_client_res.pop("amsterdam01_seattle01_isi01_grnet01_uw01_gatech01")

    sbas_rov_3node = sbas_rov_res.pop("amsterdam01_seattle01_isi01")
    sbas_rov_4node = sbas_rov_res.pop("amsterdam01_seattle01_isi01_grnet01")
    sbas_rov_5node = sbas_rov_res.pop("amsterdam01_seattle01_isi01_grnet01_uw01")
    sbas_rov_6node = sbas_rov_res.pop("amsterdam01_seattle01_isi01_grnet01_uw01_gatech01")

    cdf_data = [np.mean(_) for _ in ping_client_res.values()]
    rov_cdf_data = [np.mean(_) for _ in sbas_rov_res.values()]

    n_bins = 50

    ax.hist(sbas_3node, n_bins, density=True, cumulative=True, label='SBAS: 3 nodes', histtype='step',linestyle='solid',color='red')
    ax.hist(sbas_4node, n_bins, density=True, cumulative=True, label='SBAS: 4 nodes', histtype='step',linestyle='dashed',color='blue')
    ax.hist(sbas_5node, n_bins, density=True, cumulative=True, label='SBAS: 5 nodes', histtype='step',linestyle='dotted',color='green')
    ax.hist(sbas_6node, n_bins, density=True, cumulative=True, label='SBAS: 6 nodes', histtype='step',linestyle='solid',color='purple')
    n, bins, patches = ax.hist(cdf_data, n_bins, density=True, cumulative=True, histtype='step', label='No SBAS',linestyle='dashed',color='orange')
    # patches[0].set_xy(patches[0].get_xy()[:-1])
    


    # patches[0].set_xy(patches[0].get_xy()[:-1])
    ax_rov.hist(sbas_rov_3node, n_bins, density=True, cumulative=True, label='SBAS: 3 nodes', histtype='step',linestyle='solid',color='red')
    ax_rov.hist(sbas_rov_4node, n_bins, density=True, cumulative=True, label='SBAS: 4 nodes', histtype='step',linestyle='dashed',color='blue')
    ax_rov.hist(sbas_rov_5node, n_bins, density=True, cumulative=True, label='SBAS: 5 nodes', histtype='step',linestyle='dotted',color='green')
    ax_rov.hist(sbas_rov_6node, n_bins, density=True, cumulative=True, label='SBAS: 6 nodes', histtype='step',linestyle='solid',color='purple')
    n, bins, patches = ax_rov.hist(rov_cdf_data, n_bins, density=True, cumulative=True, histtype='step', label='No SBAS',linestyle='dashed',color='orange')
    


    ax.legend(loc='upper left', fontsize=8)
    ax.grid(True, alpha=0.35, linestyle='dashed')
    ax.set_xlabel('Resilience')
    ax.set_ylabel('CDF')
    ax.set_title('SBAS')

    ax_rov.legend(loc='upper left', fontsize=8)
    ax_rov.grid(True, alpha=0.35, linestyle='dashed')
    ax_rov.set_xlabel('Resilience')
    ax_rov.set_title('SBAS with ROV')

    fig.savefig("sbas_artifact_cdf.png", dpi=IMG_RES)


if __name__ == '__main__':
    
    sbas_sim_f = sys.argv[1]
    sbas_rov_sim_f = sys.argv[2]
    plot_compare_distribution(sbas_sim_f, sbas_rov_sim_f)