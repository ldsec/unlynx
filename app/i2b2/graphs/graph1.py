import matplotlib.pyplot as plt
import pandas as pd
import pylab as pyl

font = {'family': 'Bitstream Vera Sans',
        'size': 12}

plt.rc('font', **font)

#percentage = 100/0.9
percentage = 1
removex1 = 0
removex2 = 0.741-0.006-0.031-0.007-0.6-0.064-0.03
removex3 = 0.741-0.006-0.026-0.009-0.6-0.061-0.03

raw_data_query_one = {'h_label': ['S1', 'S2', 'S3'],                                                # Servers
            'y1_label': [0.006*percentage, 0.006*percentage, 0.006*percentage],                     # Query Parsing
            'y2_label': [0.026*percentage, 0.031*percentage, 0.026*percentage],                     # Query Tagging Com
            'y3_label': [0.008*percentage, 0.007*percentage, 0.009*percentage],                     # Query Tagging
            'y4_label': [(0.6+0.061)*percentage, (0.6+0.064)*percentage, (0.6+0.061)*percentage],   # i2b2 query
            'y5_label': [0.04*percentage, 0.03*percentage, 0.03*percentage],                        # Aggregation
            'y6_label': [0.006*percentage, 0.006*percentage, 0.006*percentage],                     # Shuffling
            'y7_label': [0.006*percentage, 0.006*percentage, 0.006*percentage],                     # Key switching
            'extra': [(0.9-0.74)*percentage, (0.9-0.74)*percentage, (0.9-0.74)*percentage],         # Unlynx processing
            'waiting':  [removex1*percentage, removex2*percentage, removex3*percentage],            # waiting
            'empty': [0, 0, 0]                                                                      # empty
            }

#percentage = 100/6.5
removex1 = 0
removex2 = 6.314-0.02-0.09-0.025-6-0.057-0.04
removex3 = 6.314-0.02-0.16-0.032-6-0.059-0.03

raw_data_query_two = {'h_label': ['S1', 'S2', 'S3'],                                           # Servers
            'y1_label': [0.02*percentage, 0.02*percentage, 0.02*percentage],                   # Query Parsing
            'y2_label': [0.128*percentage, 0.09*percentage, 0.16*percentage],                  # Query Tagging Com
            'y3_label': [0.038*percentage, 0.025*percentage, 0.032*percentage],                # Query Tagging
            'y4_label': [(6+0.061)*percentage, (6+0.057)*percentage, (6+0.059)*percentage],    # i2b2 query
            'y5_label': [0.07*percentage, 0.04*percentage, 0.03*percentage],                   # Aggregation
            'y6_label': [0.02*percentage, 0.02*percentage, 0.02*percentage],                   # Shuffling
            'y7_label': [0.02*percentage, 0.02*percentage, 0.02*percentage],                   # Key switching
            'extra': [(6.5-6.314)*percentage, (6.5-6.314)*percentage, (6.5-6.314)*percentage], # Unlynx processing
            'waiting':  [removex1*percentage, removex2*percentage, removex3*percentage],       # waiting
            'empty': [0, 0, 0]                                                                 # empty
            }


df = pd.DataFrame(raw_data_query_one, raw_data_query_one['h_label'])
#df = pd.DataFrame(raw_data_query_two, raw_data_query_two['h_label'])

# Create the general plot and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_l = pos = pyl.arange(len(df['h_label']))+.3

# Positions of the y-axis ticks (center of the bars as bar labels)
tick_pos = [i + (bar_width / 2) for i in bar_l]

# Container of all bars
bars = []

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
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
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y1_label'],
                     bar_width,
                     label='Query parsing',
                     # with alpha 0.5
                     alpha=0.8,
                     # with color
                     color='#664b39'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y2_label'],
                     bar_width,
                     # with y1_label on the left
                     left=df['y1_label'],
                     label='',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     hatch='//',
                     color='#f2d70e'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y3_label'],
                     bar_width,
                     # with y1_label and y2_label on the left
                     left=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                     label='Query Tagging',
                     # with alpha 0
                     alpha=0.5,
                     # with color
                     color='#f2d70e'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y4_label'],
                     bar_width,
                     # with y1_label, y2_label and y3_label on the left
                     left=[i + j + q for i, j, q in zip(df['y1_label'], df['y2_label'], df['y3_label'])],
                     label='i2b2 query',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#654321'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y5_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting and y5_label on the left
                     left=[i + j + q + w for i, j, q, w in zip(df['y1_label'], df['y2_label'], df['y3_label'],
                                                               df['y4_label'])],
                     label='Aggregation',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#3232FF'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['waiting'],
                     bar_width,
                     # with y1_label, y2_label, y3_label and y4_label on the left
                     left=[i + j + q + w + e for i, j, q, w, e in zip(df['y1_label'], df['y2_label'],
                                                                      df['y3_label'], df['y4_label'],
                                                                      df['y5_label'])],
                     # with alpha 0
                     alpha=0,
                     # with color
                     color='black'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y6_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting and y5_label on the left
                     left=[i + j + q + w + e + b for i, j, q, w, e, b in zip(df['y1_label'], df['y2_label'],
                                                                             df['y3_label'], df['y4_label'],
                                                                             df['y5_label'], df['waiting'])],
                     label='Result shuffling',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#92f442'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['y7_label'],
                     bar_width,
                     # with y1_label, y2_label, y3_label, y4_label, waiting and y5_label on the left
                     left=[i + j + q + w + e + b + r for i, j, q, w, e, b, r in zip(df['y1_label'], df['y2_label'],
                                                                                    df['y3_label'], df['y4_label'],
                                                                                    df['y5_label'], df['waiting'],
                                                                                    df['y6_label'])],



                     label='Result re-encryption',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     color='#d1101d'))

# Create a barh plot, in position bar_l
bars.append(ax1.barh(bar_l,
                     # using the empty data
                     df['extra'],
                     bar_width,
                     # with y1_label, y2_label and y3_label on the left
                     left=[i + j + q + w + e + b + r + p for i, j, q, w, e, b, r, p in zip(df['y1_label'],
                                                                                           df['y2_label'],
                                                                                           df['y3_label'],
                                                                                           df['y4_label'],
                                                                                           df['y5_label'],
                                                                                           df['waiting'],
                                                                                           df['y6_label'],
                                                                                           df['y7_label'])],
                     label='Unlynx processing',
                     # with alpha 0.5
                     alpha=0.5,
                     # with color
                     hatch='x',
                     color='white'))



# Set the y ticks with names
plt.yticks(tick_pos, df['h_label'])
ax1.xaxis.grid(True)

# Set the label and legends
ax1.set_xlabel("Percentage of execution", fontsize=22)
plt.legend(loc='upper center', ncol=2)

ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

# Set a buffer around the edge
plt.ylim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 0.8])

ax1.set_xlim([0, 1])
plt.axvline(x=0.741, ymin=0, ymax=10, linewidth=1, color='k')
plt.savefig('timeline_use_case_1.pdf', format='pdf')

#ax1.set_xlim([0, 7])
#plt.axvline(x=6.314, ymin=0, ymax=10, linewidth=1, color='k')
#plt.savefig('timeline_use_case_2.pdf', format='pdf')
