import pandas as pd
import matplotlib.pyplot as plt

raw_data = {'x_label': ['3', '4', '5', '6', '7'],                               # Number of servers
            'y1_label': [8, 8, 9, 9, 9],                                        # Communication
            'y2_label': [11-8, 9-8, 10-9, 11-9, 10-9],                          # Shuffle+DDH
            'y4_label': [0.1, 0.2, 0.2, 0.2, 0.2],                              # Communication
            'y3_label': [0.1-0.1, 0.25-0.2, 0.26-0.2, 0.26-0.2, 0.27-0.2],      # Collective Aggregation
            'y5_label': [0.3, 0.4, 0.6, 0.7, 0.8],                              # Communication
            'y6_label': [0.3-0.3, 0.5-0.4,	0.6-0.6, 0.7-0.7, 0.9-0.8],         # Key Switching
            'empty': [0, 0, 0, 0, 0],                                           # empty
            'y2text_label': [11, 9, 10, 11 ,10],
            'y4text_label': [0.3, 0.5, 0.6, 0.7, 0.9],
            'y6text_label': [0.1, 0.25, 0.26, 0.26, 0.27],
            'y7_label': [1.9, 1.6, 1.6, 1.2, 0.7]}

font = {'family' : 'Bitstream Vera Sans',
        'size'   : 18}

plt.rc('font', **font)

df = pd.DataFrame(raw_data, raw_data['x_label'])

# Create the general plot and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(9,7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_l = [i+1 for i in range(len(df['y1_label']))]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i+(bar_width/2) for i in bar_l]

# Container of all bars
bars = []

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the empty data
                    df['empty'],
                    # set the width
                    width=bar_width,
                    label='Communication',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='white'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    # with alpha 0.6
                    alpha=0.6,
                    # with color
                    hatch='//',
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='Shuffl. + DDT',
                    # with alpha 0.6
                    alpha=0.6,
                    yerr=df['y7_label'],
                    ecolor='black',
                    # with color
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label on the bottom
                    bottom=[i+j for i,j in zip(df['y1_label'],df['y2_label'])],
                    # with alpha 0.7
                    alpha=0.7,
                    # with color
                    hatch='//',
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y4_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label on the bottom
                    bottom=[i+j+z for i,j,z in zip(df['y1_label'],df['y2_label'],df['y3_label'])],
                    label='Collective Aggr.',
                    # with alpha 0.7
                    alpha=0.7,
                    # with color
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y5_label data
                    df['y5_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label on the bottom
                    bottom=[i+j+z+k for i,j,z,k in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'])],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#808080'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y6_label data
                    df['y6_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label on the bottom
                    bottom=[i+j+z+k+l for i,j,z,k,l in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'],df['y5_label'])],
                    label='Key Switching',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#808080'))

# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'])
ax1.yaxis.grid(True)

# Labelling
height=[0, 0, 0, 0, 0, 0]
for rects in bars:
    i=0
    for rect in rects:
        height[i]+=rect.get_height()
        i+=1

ax1.text(tick_pos[0] - 0.12, height[0] - height[0] / 2, str(df['y2text_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.06, height[1] - height[1] / 2, str(df['y2text_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.12, height[2] - height[2] / 2, str(df['y2text_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.12, height[3] - height[3] / 2, str(df['y2text_label'][3]), color='black', fontweight='bold')
ax1.text(tick_pos[4] - 0.12, height[4] - height[4] / 2, str(df['y2text_label'][4]), color='black', fontweight='bold')

ax1.text(tick_pos[0] + 0.3, height[0] - height[0] / 10, str(df['y4text_label'][0]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[1] + 0.3, height[1] - height[1] / 10, str(df['y4text_label'][1]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[2] + 0.3, height[2] - height[2] / 10, str(df['y4text_label'][2]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[3] + 0.3, height[3] - height[3] / 10, str(df['y4text_label'][3]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[4] + 0.3, height[4] - height[4] / 8, str(df['y4text_label'][4]), color='#8B4513', fontweight='bold')

ax1.text(tick_pos[0] - 0.15, height[0] + height[0] / 40, str(df['y6text_label'][0]), color='#808080', fontweight='bold')
ax1.text(tick_pos[1] - 0.21, height[1] + height[1] / 40, str(df['y6text_label'][1]), color='#808080', fontweight='bold')
ax1.text(tick_pos[2] - 0.21, height[2] + height[2] / 40, str(df['y6text_label'][2]), color='#808080', fontweight='bold')
ax1.text(tick_pos[3] - 0.21, height[3] + height[3] / 40, str(df['y6text_label'][3]), color='#808080', fontweight='bold')
ax1.text(tick_pos[4] - 0.21, height[4] + height[4] / 40, str(df['y6text_label'][4]), color='#808080', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
ax1.set_xlabel("Number of servers in the collective authority", fontsize=22)
plt.legend(loc=1,fontsize=20)


ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

# Set a buffer around the edge
plt.xlim([min(tick_pos)-bar_width, max(tick_pos)+bar_width+0.2])
plt.ylim([0,20])

plt.savefig('vary_num_servers.pdf', format='pdf')