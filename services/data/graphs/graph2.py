import matplotlib.pyplot as plt
import pandas as pd


def addComma(v, index):
    v = v[:index] + ',' + v[index:]
    return v


font = {'family': 'Bitstream Vera Sans',
        'size': 18}

plt.rc('font', **font)

raw_data = {'x_label': ['10', '100', '1K', '10K', '100K'],  # Number responses
            'y2_label': [0.3, 2, 17, 160, 1671],  # Shuffling + Verification
            'y1_label': [0.3, 1.1, 10, 98, 987],  # Shuffling + DDH Proof
            'y3_label': [0.3, 0.3, 0.5, 2.1, 20]}  # Other

df = pd.DataFrame(raw_data, raw_data['x_label'])

# Create the general plot and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(9, 7))

# Set the bar width
bar_width = 0.5

# Positions of the left bar-boundaries
bar_l = [i + 1 for i in range(len(df['y1_label']))]

# Positions of the x-axis ticks (center of the bars as bar labels)
tick_pos = [i + (bar_width / 2) for i in bar_l]

# Container of all bars
bars = []
# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y1_label data
                    df['y1_label'],
                    # set the width
                    width=bar_width,
                    label='Shuffl. + DDT Proof',
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#F4561D'
                    ))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='Shuffl. + DDT Verif.',
                    # with alpha 0.6
                    alpha=0.6,
                    # with color
                    color='#cccc00'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label and y2_label on the bottom
                    bottom=[i + j for i, j in zip(df['y1_label'], df['y2_label'])],
                    label='Other',
                    # with alpha 0.6
                    alpha=0.6,
                    # with color
                    color='#3232FF'))

# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'])
ax1.set_yscale('log')
ax1.yaxis.grid(True)

# Labelling
height = [0, 0, 0, 0, 0]
for rects in bars:
    i = 0
    for rect in rects:
        height[i] += rect.get_height()
        i += 1

ax1.text(tick_pos[0] - 0.16, height[0] + height[0] / 5, str(df['y3_label'][0]), color='#3232FF', fontweight='bold')
ax1.text(tick_pos[1] - 0.16, height[1] + height[1] / 5, str(df['y3_label'][1]), color='#3232FF', fontweight='bold')
ax1.text(tick_pos[2] - 0.16, height[2] + height[2] / 5, str(df['y3_label'][2]), color='#3232FF', fontweight='bold')
ax1.text(tick_pos[3] - 0.16, height[3] + height[3] / 5, str(df['y3_label'][3]), color='#3232FF', fontweight='bold')
ax1.text(tick_pos[4] - 0.12, height[4] + height[4] / 5, str(int(df['y3_label'][4])), color='#3232FF', fontweight='bold')

ax1.text(tick_pos[0] - 0.15, height[0] - height[0] / 1.2, str(df['y1_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.05, height[1] - height[1] / 1.2, str(int(df['y1_label'][1])), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.12, height[2] - height[2] / 1.2, str(int(df['y1_label'][2])), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.12, height[3] - height[3] / 1.2, str(int(df['y1_label'][3])), color='black', fontweight='bold')
ax1.text(tick_pos[4] - 0.19, height[4] - height[4] / 1.2, str(int(df['y1_label'][4])), color='black', fontweight='bold')

ax1.text(tick_pos[0] - 0.15, height[0] - height[0] / 1.6 + 0.01, str(df['y2_label'][0]), color='black',
         fontweight='bold')
ax1.text(tick_pos[1] - 0.15, height[1] - height[1] / 1.9, str(df['y2_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.12, height[2] - height[2] / 2, str(int(df['y2_label'][2])), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.19, height[3] - height[3] / 2, str(int(df['y2_label'][3])), color='black', fontweight='bold')
ax1.text(tick_pos[4] - 0.30, height[4] - height[4] / 2, addComma(str(int(df['y2_label'][4])), 1), color='black',
         fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
ax1.yaxis.set_label_coords(-0.11, 0.5)
ax1.set_xlabel("Number of responses processed per server", fontsize=22)
plt.legend(loc='upper left')

ax1.tick_params(axis='x', labelsize=22)
ax1.tick_params(axis='y', labelsize=22)

labels = [item.get_text() for item in ax1.get_yticklabels()]
labels[0] = '0'
labels[1] = '0.1'
labels[2] = '1'
labels[3] = '10'
labels[4] = '100'
labels[5] = '1K'
labels[6] = '10K'
ax1.set_yticklabels(labels)

# Set a buffer around the edge
plt.xlim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 0.2])

plt.savefig('proof_vary_num_responses.pdf', format='pdf')
