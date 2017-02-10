import pandas as pd
import matplotlib.pyplot as plt

raw_data = {'x_label': ['1', '10', '20', '100', '1K'],                          # Number of groups
            'y1_label': [0.1, 0.1, 0.1, 0.2, 0.65],                             # Communication
            'y2_label': [0.1-0.1, 0.1-0.1, 0.2-0.1, 0.2-0.2, 0.6-0.6],          # Collective Aggregation
            'y3_label': [0.2, 0.2, 0.3, 0.7, 2.54],                             # Communication
            'y4_label': [0.3-0.2, 0.3-0.2, 0.4-0.3, 0.8-0.7, 3.2-2.54],         # Key Switching
            'empty': [0, 0, 0, 0, 0],                                           # empty
            'y2text_label': [0.1, 0.1, 0.2, 0.2, 0.6],
            'y4text_label': [0.3, 0.3, 0.4, 0.8, 3.2]}

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
                    # with alpha 0.7
                    alpha=0.7,
                    # with color
                    hatch='//',
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='Collective Aggr.',
                    # with alpha 0.7
                    alpha=0.7,
                    # with color
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label on the bottom
                    bottom=[i+j for i,j in zip(df['y1_label'],df['y2_label'])],
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    hatch='//',
                    color='#808080'))


# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label on the bottom
                    bottom=[i+j+z for i,j,z in zip(df['y1_label'],df['y2_label'],df['y3_label'])],
                    label='Key Switching',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#808080'))

# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'])
ax1.yaxis.grid(True)

# Labelling
height=[0, 0, 0, 0, 0]
for rects in bars:
    i=0
    for rect in rects:
        height[i]+=rect.get_height()
        i+=1

ax1.text(tick_pos[0]+0.3,0.01, str(df['y2text_label'][0]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[1]+0.3,0.01, str(df['y2text_label'][1]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[2]+0.3,0.05, str(df['y2text_label'][2]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[3]+0.3,0.05, str(df['y2text_label'][3]), color='#8B4513', fontweight='bold')
ax1.text(tick_pos[4]+0.3,0.3, str(df['y2text_label'][4]), color='#8B4513', fontweight='bold')

ax1.text(tick_pos[0] - 0.15, height[0] - height[0] / 1.5, str(df['y4text_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.15, height[1] - height[1] / 1.5, str(df['y4text_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.15, height[2] - height[2] / 2, str(df['y4text_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.15, height[3] - height[3] / 2, str(df['y4text_label'][3]), color='black', fontweight='bold')
ax1.text(tick_pos[4] - 0.15, height[4] - height[4] / 2, str(df['y4text_label'][4]), color='black', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
ax1.set_xlabel("Number of groups", fontsize=22)
plt.legend(loc='upper left')

ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

labels = [item.get_text() for item in ax1.get_yticklabels()]

# Set a buffer around the edge
plt.xlim([min(tick_pos)-bar_width, max(tick_pos)+bar_width+0.2])

plt.savefig('vary_num_groups.pdf', format='pdf')