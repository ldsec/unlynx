import pandas as pd
import matplotlib.pyplot as plt

raw_data = {'x_label': ['1', '10', '20', '100', '1K'],                                      # Number groups
            'y1_label': [0.9, 0.9, 0.9, 1.1, 3.8],                                          # Collective Aggregation Verification
            'y2_label': [0.1, 0.1, 0.1, 0.3, 2.5],                                          # Key Switching Proofs
            'y3_label': [0.1, 0.1, 0.2, 0.5, 3.6]}                                          # Key Switching Verification

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
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    label='Collective Aggr. Verif.',
                    # with alpha 0.7
                    alpha=0.7,
                    # with color
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='Key Switching Proof',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#808080'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label and y2_label on the bottom
                    bottom=[i+j for i,j in zip(df['y1_label'],df['y2_label'])],
                    label='Key Switching Verif.',
                    # with alpha 0.6
                    alpha=0.6,
                    # with color
                    color='#2C6638'))

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

ax1.text(tick_pos[0] - 0.16, height[0] + height[0] / 8, str(df['y3_label'][0]), color='#2C6638', fontweight='bold')
ax1.text(tick_pos[1] - 0.16, height[1] + height[1] / 8, str(df['y3_label'][1]), color='#2C6638', fontweight='bold')
ax1.text(tick_pos[2] - 0.16, height[2] + height[2] / 8, str(df['y3_label'][2]), color='#2C6638', fontweight='bold')
ax1.text(tick_pos[3] - 0.14, height[3] + height[3] / 8, str(df['y3_label'][3]), color='#2C6638', fontweight='bold')
ax1.text(tick_pos[4] - 0.16, height[4] - 2, str(df['y3_label'][4]), color='black', fontweight='bold')

ax1.text(tick_pos[0] - 0.16, height[0] - height[0] / 1.2, str(df['y1_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.16, height[1] - height[1] / 1.2, str(df['y1_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.16, height[2] - height[2] / 1.2, str(df['y1_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.16, height[3] - height[3] / 1.2, str(df['y1_label'][3]), color='black', fontweight='bold')
ax1.text(tick_pos[4] - 0.16, height[4] - height[4] / 1.2, str(df['y1_label'][4]), color='black', fontweight='bold')

ax1.text(tick_pos[0] + 0.3, height[0] - height[0] / 4, str(df['y2_label'][0]), color='#808080', fontweight='bold')
ax1.text(tick_pos[1] + 0.3, height[1] - height[1] / 4, str(df['y2_label'][1]), color='#808080', fontweight='bold')
ax1.text(tick_pos[2] + 0.3, height[2] - height[2] / 4, str(df['y2_label'][2]), color='#808080', fontweight='bold')
ax1.text(tick_pos[3] + 0.3, height[3] - height[3] / 2.7, str(df['y2_label'][3]), color='#808080', fontweight='bold')
ax1.text(tick_pos[4] - 0.16, height[4] - height[4] / 2, str(df['y2_label'][4]), color='black', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
ax1.set_xlabel("Number of groups", fontsize=22)
plt.legend(loc='upper left')

labels = [item.get_text() for item in ax1.get_yticklabels()]

ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

# Set a buffer around the edge
plt.xlim([min(tick_pos)-bar_width, max(tick_pos)+bar_width+0.2])

plt.savefig('proof_vary_num_groups.pdf', format='pdf')