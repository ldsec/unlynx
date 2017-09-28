import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

percentage = 1
removex1 = 2.4 - 0.04 - 0.14 - 0.04 - 1.8 - 0.147 - 0.04 - 0.04 - 0.04
removex2 = 3.6 - 0.04 - 0.14 - 0.04 - 2.3 - 0.604 - 0.07 - 0.04 - 0.04
removex3 = 9.6 - 0.04 - 0.14 - 0.04 - 3.4 - 3.4 - 0.68 - 0.04 - 0.04

raw_data_query_one = {'x_label': ['\n\n\n1x', '\n\n\n100x', '\n\n\n1000x'],            # number of entries
                      #i2b2 clear timeline
                      'y1_label_clear': [0.04, 0.04, 0.04],          # Query Parsing
                      'y2_label_clear': [1.8, 2.3, 3.4],               # i2b2 query

                      'total_clear':    [1.8, 2.3, 3.4],

                      #i2b2 medco timeline
                      'y1_label_medco': [0.04, 0.04, 0.04],                  # Query Parsing
                      'y2_label_medco': [0.14, 0.14, 0.14],                  # Query Tagging Com
                      'y3_label_medco': [0.04, 0.04, 0.04],                  # Query Tagging
                      'y4_label_medco': [1.8, 2.3, 3.4],                       # i2b2 query
                      'y5_label_medco': [0.147, 0.604, 3.4],                 # i2b2 query
                      'y6_label_medco': [0.04, 0.07, 0.68],                  # Aggregation
                      'y7_label_medco': [0.04, 0.04, 0.04],                  # Shuffling
                      'y8_label_medco': [0.04, 0.04, 0.04],                  # Key switching
                      'waiting_medco':  [removex1, removex2, removex3],      # waiting

                      'total_medco':    [2.4, 3.6, 9.6],

                      'empty': [0, 0, 0]                                     # empty
}

font = {'family': 'Bitstream Vera Sans',
        'size': 26}

plt.rc('font', **font)

df = pd.DataFrame(raw_data_query_one, raw_data_query_one['x_label'])
add = 0.1

N = 3
ind = np.arange(N)  # The x locations for the groups

# Create the general blog and the "subplots" i.e. the bars
fig, ax1 = plt.subplots(1, figsize=(16, 12))

# Set the bar width
bar_width = 0.3

# Container of all bars
bars = []

#i2b2 clear

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y1_label data
                    df['y1_label_clear'],
                    # set the width
                    width=bar_width,
                    # with alpha 1
                    alpha=0.8,
                    # with color
                    color='#664b39'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(ind,
                    # using the y1_label data
                    df['y2_label_clear'],
                    # set the width
                    width=bar_width,
                    bottom=df['y1_label_clear'],
                    # with alpha 1
                    alpha=0.5,
                    # with color
                    color='#654321'))

#MedCo

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['empty'],
                     bar_width,
                     label='Communication',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     hatch='//',
                     color='white'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['y1_label_medco'],
                     bar_width,
                     label='Query parsing',
                     # with alpha 0.5
                     alpha=0.8,
                     # with color
                     color='#664b39'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['y2_label_medco'],
                     bar_width,
                     # with y1_label on the left
                     bottom=df['y1_label_medco'],
                     label='',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     hatch='//',
                     color='#f2d70e'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['y3_label_medco'],
                     bar_width,
                     # with y1_label and y2_label on the left
                     bottom=[i + j for i, j in zip(df['y1_label_medco'], df['y2_label_medco'])],
                     label='Query Tagging',
                     # with alpha 0
                     alpha=0.5,
                     # with color
                     color='#f2d70e'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['y4_label_medco'],
                     bar_width,
                     # with y1_label, y2_label and y3_label on the left
                     bottom=[i + j + q for i, j, q in zip(df['y1_label_medco'], df['y2_label_medco'], df['y3_label_medco'])],
                     label='i2b2 query',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#654321'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                    # using the empty data
                    df['y5_label_medco'],
                    bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, waiting and y5_label on the left
                    bottom=[i + j + q + w for i, j, q, w in zip(df['y1_label_medco'], df['y2_label_medco'], df['y3_label_medco'],
                                                                df['y4_label_medco'])],
                    label='Encrypted flag retrieval',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#4C8E8B'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['y6_label_medco'],
                     bar_width,
                     # with y1_label, y2_label, y3_label and y4_label on the left
                     bottom=[i + j + q + w + e for i, j, q, w, e in zip(df['y1_label_medco'], df['y2_label_medco'],
                                                                       df['y3_label_medco'], df['y4_label_medco'],
                                                                       df['y5_label_medco'])],
                     label='Aggregation',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#3232FF'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['waiting_medco'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting and y5_label on the left
                     bottom=[i + j + q + w + e + b for i, j, q, w, e, b in zip(df['y1_label_medco'], df['y2_label_medco'],
                                                                              df['y3_label_medco'], df['y4_label_medco'],
                                                                              df['y5_label_medco'], df['y6_label_medco'])],
                     label='Inter-server synchronization',
                     # with alpha 0
                     alpha=0.1,
                     # with color
                     color='black'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['y7_label_medco'],
                     bar_width,
                        bottom=[i + j + q + w + e + b + r for i, j, q, w, e, b, r in zip(df['y1_label_medco'], df['y2_label_medco'],
                                                                                     df['y3_label_medco'], df['y4_label_medco'],
                                                                                     df['y5_label_medco'], df['y6_label_medco'],
                                                                                     df['waiting_medco'])],
                     label='Result shuffling',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#92f442'))

# Create a barh plot, in position bar_l
bars.append(ax1.bar(ind + bar_width,
                     # using the empty data
                     df['y8_label_medco'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting and y5_label on the left
                     bottom=[i + j + q + w + e + b + r + o for i, j, q, w, e, b, r, o in zip(df['y1_label_medco'], df['y2_label_medco'],
                                                                                    df['y3_label_medco'], df['y4_label_medco'],
                                                                                    df['y5_label_medco'], df['y6_label_medco'],
                                                                                    df['waiting_medco'], df['y7_label_medco'])],



                     label='Result re-encryption',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#d1101d'))

# Labelling
ax1.text(ind[0] + 0.06, df['total_clear'][0]+0.1,
         str(df['total_clear'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + 0.06, df['total_clear'][1]+0.1,
         str(df['total_clear'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + 0.06, df['total_clear'][2]+0.1,
         str(df['total_clear'][2]), color='black', fontweight='bold')

ax1.text(ind[0]+bar_width/2-0.18, df['total_clear'][0]-df['total_clear'][0] - 0.5,
         'Insec. i2b2', color='black', fontsize=20, fontweight='bold', rotation='40')
ax1.text(ind[1]+bar_width/2-0.18, df['total_clear'][1]-df['total_clear'][1] - 0.5,
         'Insec. i2b2', color='black', fontsize=20, fontweight='bold', rotation='40')
ax1.text(ind[2]+bar_width/2-0.18, df['total_clear'][2]-df['total_clear'][2] - 0.5,
         'Insec. i2b2', color='black', fontsize=20, fontweight='bold', rotation='40')


ax1.text(ind[0] + bar_width + 0.07, df['total_medco'][0]+0.1,
         str(df['total_medco'][0]), color='black', fontweight='bold')
ax1.text(ind[1] + bar_width + 0.07, df['total_medco'][1]+0.1,
         str(df['total_medco'][1]), color='black', fontweight='bold')
ax1.text(ind[2] + bar_width + 0.07, df['total_medco'][2]+0.1,
         str(df['total_medco'][2]), color='black', fontweight='bold')

ax1.text(ind[0]+3*bar_width/2-0.12, df['total_medco'][0]-df['total_medco'][0] - 0.4,
         'MedCo', color='black', fontsize=20, fontweight='bold', rotation='40')
ax1.text(ind[1]+3*bar_width/2-0.12, df['total_medco'][1]-df['total_medco'][1] - 0.4,
         'MedCo', color='black', fontsize=20, fontweight='bold', rotation='40')
ax1.text(ind[2]+3*bar_width/2-0.12, df['total_medco'][2]-df['total_medco'][2] - 0.4,
         'MedCo', color='black', fontsize=20, fontweight='bold', rotation='40')

# Set the x ticks with names
ax1.set_xticks(ind + bar_width)
ax1.set_xticklabels(df['x_label'])
ax1.set_xlim([0, ind[2] + bar_width + bar_width + bar_width])
ax1.set_ylim([0, 12])

# Labelling

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=32)
ax1.set_xlabel("Size of the database", fontsize=32)
plt.legend(loc='upper left', fontsize=26)

ax1.tick_params(axis='x', labelsize=32)
ax1.tick_params(axis='y', labelsize=32)

fig.subplots_adjust(bottom=0.21) # or whatever

plt.savefig('scalabilty_data_use_case_1_a.pdf', format='pdf')
