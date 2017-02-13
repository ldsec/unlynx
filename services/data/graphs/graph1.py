import matplotlib.pyplot as plt
import pandas as pd

font = {'family': 'Bitstream Vera Sans',
        'size': 18}

plt.rc('font', **font)

raw_data = {'x_label': ['10', '100', '1K', '10K', '100K'],  # Number responses
            'y1_label': [0.54, 0.76, 1.51, 7.63, 69.2],  # Communication
            'y2_label': [0.6 - 0.54, 1 - 0.76, 2 - 1.51, 12 - 7.63, 91 - 69.2],  # Shuffling + DDH
            'y3_label': [0.5, 0.5, 0.5, 0.5, 0.5],  # Other
            'empty': [0, 0, 0, 0, 0],  # empty
            'y2text_label': [0.6, 1, 2, 12, 91]}

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
                    # with alpha 0.5
                    alpha=0.5,
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
                    # with alpha 0.5
                    alpha=0.5,
                    # with color
                    color='#F4561D'))

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

ax1.text(tick_pos[0] + 0.3, height[0] - 0.35, str(df['y3_label'][0]), color='#3232FF', fontweight='bold')
ax1.text(tick_pos[1] + 0.3, height[1] - 0.35, str(df['y3_label'][1]), color='#3232FF', fontweight='bold')
ax1.text(tick_pos[2] + 0.3, height[2] - 0.35, str(df['y3_label'][2]), color='#3232FF', fontweight='bold')
ax1.text(tick_pos[3] + 0.3, height[3] - 0.35, str(df['y3_label'][3]), color='#3232FF', fontweight='bold')
ax1.text(tick_pos[4] + 0.3, height[4] - 20, str(df['y3_label'][4]), color='#3232FF', fontweight='bold')

ax1.text(tick_pos[0] - 0.15, height[0] - height[0] / 1.2, str(df['y2text_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.05, height[1] - height[1] / 1.2, str(int(df['y2text_label'][1])), color='black',
         fontweight='bold')
ax1.text(tick_pos[2] - 0.05, height[2] - height[2] / 1.2, str(int(df['y2text_label'][2])), color='black',
         fontweight='bold')
ax1.text(tick_pos[3] - 0.12, height[3] - height[3] / 1.2, str(int(df['y2text_label'][3])), color='black',
         fontweight='bold')
ax1.text(tick_pos[4] - 0.12, height[4] - height[4] / 1.2, str(int(df['y2text_label'][4])), color='black',
         fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
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
ax1.set_yticklabels(labels)

# Set a buffer around the edge
plt.xlim([min(tick_pos) - bar_width, max(tick_pos) + bar_width + 0.2])

plt.savefig('vary_num_responses.pdf', format='pdf')
