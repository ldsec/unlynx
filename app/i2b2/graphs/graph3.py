import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

raw_data = {
    'x_label':  ['1x', '2x', '4x'],
    'y1_label': [1, 1, 1],                  # Dummy Generation
    'y2_label': [162.6, 322.8, 484.4],      # Encryption
    'y3_label': [77.5, 156.4, 310.9],       # Data tagging
    'y4_label': [8.4, 8.4, 8.4],            # Loading
    'total': [1, 1, 1],
}

font = {'family': 'Bitstream Vera Sans',
        'size': 26}

plt.rc('font', **font)

df = pd.DataFrame(raw_data, raw_data['x_label'])

N = 3
ind = np.arange(N)  # The x locations for the groups

# Create the general blog and the "subplots" i.e. the bars
fig, ax1 = plt.subplots(1, figsize=(14, 12))

# Set the bar width
bar_width = 0.5

# Container of all bars
bars = []

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    label='Dummy generation',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#3F62AD'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    label='Encryption',
                    bottom=df['y1_label'],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#4C8E8B'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    label='Data tagging',
                    bottom=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#A747B8'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y2_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    bottom=[i + j + k for i, j, k in zip(df['y1_label'], df['y2_label'], df['y3_label'])],
                    label="Loading",
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#3232FF'))


# Set the x ticks with names
ax1.set_xticks(ind + bar_width/2)
ax1.set_xticklabels(df['x_label'])
ax1.set_ylim([0, 1000])
ax1.set_xlim([-bar_width/2, ind[2] + bar_width + bar_width/2])

# Labelling
ax1.text(ind[0] + bar_width/2 - 0.04, df['total'][0]+1,
         str(df['total'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width/2 - 0.04, df['total'][1]+2,
         str(df['total'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width/2 - 0.04, df['total'][2]+4,
         str(df['total'][2]), color='black', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=32)
ax1.set_xlabel("Size of the database", fontsize=32)
plt.legend(loc='upper left', fontsize=32)

ax1.tick_params(axis='x', labelsize=32)
ax1.tick_params(axis='y', labelsize=32)

plt.savefig('ETL.pdf', format='pdf')
