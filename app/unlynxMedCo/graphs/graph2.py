import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

raw_data = {
    'x_label':  ['5', '10', '100', '500'],
    'y1_label': [0, 0, 0, 0],                 # ib2b Insecure
    'y2_label': [0.3, 0.4, 2.8, 12.9],        # DB traffic
    'y3_label': [0, 0, 0, 0],                 # Secure Protocols
    'y4_label': [0, 0, 0, 0],                 # medco
    'y5_label': [0.3, 0.4, 2.8, 12.9],        # DB traffic
    'y6_label': [0.095, 0.1, 0.26, 0.956],    # Secure Protocols
    'y7_label': [0, 0, 0, 0],                 # medco+
    'y8_label': [8.4, 8.4, 8.4, 8.4],         # DB traffic
    'y9_label': [65.4, 66.3, 68.4, 70.9],     # Secure Protocols
    'hatch_i2b2': [0, 0, 0, 0],               # hatch i2b2
    'hatch_unlynx': [0, 0, 0, 0],             # hatch unlynx
    'total1': [0.3, 0.4, 2.8, 12.9],          # i2b2 Insecure
    'total2': [0.4, 0.5, 3.1, 13.8],          # total medco
    'total3': [73.8, 74.7, 76.8, 79.3],       # total medco+
}

font = {'family': 'Bitstream Vera Sans',
        'size': 26}

plt.rc('font', **font)

df = pd.DataFrame(raw_data, raw_data['x_label'])

N = 4
ind = np.arange(N)  # The x locations for the groups

# Create the general blog and the "subplots" i.e. the bars
fig, ax1 = plt.subplots(1, figsize=(14, 12))

# Set the bar width
bar_width = 0.3

# Container of all bars
bars = []

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    label='Insecure i2b2',
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    color='#1abc78'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y1_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    bottom=df['y1_label'],
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#1abc78'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y1_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    bottom=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='#1abc78'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                    # using the y3_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    label='MedCo',
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                    # using the y3_label data
                    df['y5_label'],
                    # set the width
                    width=bar_width,
                    bottom=df['y4_label'],
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                    # using the y3_label data
                    df['y6_label'],
                    # set the width
                    width=bar_width,
                    bottom=[i + j for i, j in zip(df['y4_label'], df['y5_label'])],
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width + bar_width,
                    # using the y3_label data
                    df['y7_label'],
                    # set the width
                    width=bar_width,
                    label='MedCo+',
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    color='#bc1a1a'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width + bar_width,
                    # using the y3_label data
                    df['y8_label'],
                    # set the width
                    width=bar_width,
                    bottom=df['y7_label'],
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#bc1a1a'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width + bar_width,
                    # using the y3_label data
                    df['y9_label'],
                    # set the width
                    width=bar_width,
                    bottom=[i + j for i, j in zip(df['y7_label'], df['y8_label'])],
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='#bc1a1a'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y2_label data
                    df['hatch_i2b2'],
                    # set the width
                    width=bar_width,
                    bottom=[i + j + k for i, j, k in zip(df['y1_label'], df['y2_label'], df['y3_label'])],
                    label="DB traffic",
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='white'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                    # using the y2_label data
                    df['hatch_unlynx'],
                    # set the width
                    width=bar_width,
                    bottom=[i + j + k for i, j, k in zip(df['y4_label'], df['y5_label'], df['y6_label'])],
                    label="Secure protocols",
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    hatch='x',
                    color='white'))

# Set the x ticks with names
ax1.set_xticks(ind + bar_width + bar_width/2)
ax1.set_xticklabels(df['x_label'])
ax1.set_yscale('symlog', basey=10)
ax1.set_ylim([0, 10000])
ax1.set_xlim([0, ind[3] + bar_width + bar_width + bar_width])

# Labelling
ax1.text(ind[0] + bar_width/2 - 0.11, df['total1'][0]+0.05,
         str(df['total1'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width/2 - 0.11, df['total1'][1]+0.05,
         str(df['total1'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width/2 - 0.11, df['total1'][2]+0.2,
         str(df['total1'][2]), color='black', fontweight='bold')
ax1.text(ind[3] + bar_width/2 - 0.20, df['total1'][3]+1,
         str(df['total1'][3]), color='black', fontweight='bold')

ax1.text(ind[0] + bar_width + bar_width/2 - 0.11, df['total2'][0]+0.05,
         str(df['total2'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width + bar_width/2 - 0.11, df['total2'][1]+0.05,
         str(df['total2'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width + bar_width/2 - 0.11, df['total2'][2]+0.2,
         str(df['total2'][2]), color='black', fontweight='bold')
ax1.text(ind[3] + bar_width + bar_width/2 - 0.17, df['total2'][3]+1,
         str(df['total2'][3]), color='black', fontweight='bold')

ax1.text(ind[0] + bar_width + bar_width + bar_width/2 - 0.17, df['total3'][0]+4,
         str(df['total3'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width + bar_width + bar_width/2 - 0.17, df['total3'][1]+4,
         str(df['total3'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width + bar_width + bar_width/2 - 0.17, df['total3'][2]+4,
         str(df['total3'][2]), color='black', fontweight='bold')
ax1.text(ind[3] + bar_width + bar_width + bar_width/2 - 0.20, df['total3'][3]+4,
         str(df['total3'][3]), color='black', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Network traffic (MB)", fontsize=32)
ax1.set_xlabel("Number of query parameters", fontsize=32)
plt.legend(loc='upper left', fontsize=32)

ax1.tick_params(axis='x', labelsize=32)
ax1.tick_params(axis='y', labelsize=32)

plt.savefig('network_traffic.pdf', format='pdf')
