import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

raw_data_query_one = {
    'x_label':  ['1x', '2x', '4x'],
    'y1_label': [1.8, 1.9, 2],          # Insecure i2b2
    'y2_label': [2.4, 2.4, 2.6],        # Without DDT
    'y3_label': [90.9, 180.6, 351.3],   # With DDT
}

raw_data_query_two = {
    'x_label':  ['1x', '2x', '4x'],
    'y1_label': [6.1, 6.4, 6.6],      # Insecure i2b2
    'y2_label': [6.7, 7.1, 7.3],      # Without DDT
    'y3_label': [91.6, 180.7, 357.5], # With DDT
}

font = {'family': 'Bitstream Vera Sans',
        'size': 26}

plt.rc('font', **font)

df = pd.DataFrame(raw_data_query_one, raw_data_query_one['x_label'])
add = 0.1

#df = pd.DataFrame(raw_data_query_two, raw_data_query_two['x_label'])
#add = 1

N = 3
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
bars.append(ax1.bar(ind + bar_width,
                    # using the y3_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    label='MedCo',
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind + bar_width + bar_width,
                    # using the y2_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    label='MedCo+',
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    color='#bc1a1a'))

# Set the x ticks with names
ax1.set_xticks(ind + bar_width + bar_width/2)
ax1.set_xticklabels(df['x_label'])
ax1.set_yscale('symlog', basey=10)
ax1.set_ylim([0, 100000])
ax1.set_xlim([0, ind[2] + bar_width + bar_width + bar_width])

# Labelling
ax1.text(ind[0] + bar_width/2 - 0.08, df['y1_label'][0]+add,
         str(df['y1_label'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width/2 - 0.08, df['y1_label'][1]+add,
         str(df['y1_label'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width/2 - 0.08, df['y1_label'][2]+add,
         str(df['y1_label'][2]), color='black', fontweight='bold')

ax1.text(ind[0] + bar_width + bar_width/2 - 0.08, df['y2_label'][0]+add,
         str(df['y2_label'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width + bar_width/2 - 0.08, df['y2_label'][1]+add,
         str(df['y2_label'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width + bar_width/2 - 0.08, df['y2_label'][2]+add,
         str(df['y2_label'][2]), color='black', fontweight='bold')

ax1.text(ind[0] + bar_width + bar_width + bar_width/2 - 0.12, df['y3_label'][0]+8,
         str(df['y3_label'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width + bar_width + bar_width/2 - 0.16, df['y3_label'][1]+16,
         str(df['y3_label'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width + bar_width + bar_width/2 - 0.16, df['y3_label'][2]+32,
         str(df['y3_label'][2]), color='black', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=32)
ax1.set_xlabel("Size of the database", fontsize=32)
plt.legend(loc='upper left', fontsize=32)

ax1.tick_params(axis='x', labelsize=32)
ax1.tick_params(axis='y', labelsize=32)

plt.savefig('scalabilty_data_use_case_1.pdf', format='pdf')
#plt.savefig('scalabilty_data_use_case_2.pdf', format='pdf')
