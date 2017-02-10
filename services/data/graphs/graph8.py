import pandas as pd
import matplotlib.pyplot as plt

raw_data = {#'x_label': ['Baseline', '50% proofs', 'Single server\'s\nproofs', 'No proofs', 'Pre-aggregated', 'Groups in\nclear'],
            #'y1_label': [8.1, 8.1, 8.1, 8.1, 0, 0],                                         # Shuffling
            #'y2_label': [46.6, 23.3, 15.5, 0, 0, 0],                                        # Shuffling Proof
            #'y3_label': [75.6, 37.8, 25.2, 0, 0, 0],                                        # Shuffling Verif.
            #'y4_label': [3.3, 3.3, 3.3, 3.3, 1.0, 0],                                       # DDH
            #'y5_label': [3, 1.5, 1.0, 0, 0, 0],                                             # DDH Proof
            #'y6_label': [4, 2, 1.3, 0, 0, 0],                                               # DDH Verif.
            #'y7_label': [0.1, 0.1, 0.1, 0.1, 0.1, 0.1],                                     # Collective Aggr.
            #'y8_label': [0, 0, 0, 0, 0, 0],                                                 # Collective Aggr. Proof
            #'y9_label': [0.9, 0.45, 0.3, 0, 0.9, 0.9],                                      # Collective Aggr. Verif.
            #'y10_label': [0.3, 0.3, 0.3, 0.3, 0.3, 0.3],                                    # Key Switching
            #'y11_label': [0.1, 0.05, 0,	0, 0.1, 0.1],                                    # Key Switching Proof
            #'y12_label': [0.1, 0.05, 0,	0, 0.1, 0.1],                                    # Key Switching Verif.
            #'y_label': [142, 77, 55, 12, 3, 3]}
            'x_label': ['Baseline', '50% proofs', 'Single server\'s\nproofs', 'No proofs'],
            'y1_label': [8.1, 8.1, 8.1, 8.1],                                               # Shuffling
            'y2_label': [46.6, 23.3, 15.5, 0],                                              # Shuffling Proof
            'y3_label': [75.6, 37.8, 25.2, 0],                                              # Shuffling Verif.
            'y4_label': [3.3, 3.3, 3.3, 3.3],                                               # DDH
            'y5_label': [3, 1.5, 1.0, 0],                                                   # DDH Proof
            'y6_label': [4, 2, 1.3, 0],                                                     # DDH Verif.
            'y7_label': [0.1, 0.1, 0.1, 0.1],                                               # Collective Aggr.
            'y8_label': [0, 0, 0, 0],                                                       # Collective Aggr. Proof
            'y9_label': [0.9, 0.45, 0.3, 0],                                                # Collective Aggr. Verif.
            'y10_label': [0.3, 0.3, 0.3, 0.3],                                              # Key Switching
            'y11_label': [0.1, 0.05, 0,	0],                                                 # Key Switching Proof
            'y12_label': [0.1, 0.05, 0,	0],                                                 # Key Switching Verif.
            'y_label': [142, 77, 55, 12]}

font = {'family' : 'Bitstream Vera Sans',
        'size'   : 22}

plt.rc('font', **font)

df = pd.DataFrame(raw_data, raw_data['x_label'])

# Create the general plot and the "subplots" i.e. the bars
f, ax1 = plt.subplots(1, figsize=(14,14))

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
                    label='Shuffling',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y2_label data
                    df['y2_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label on the bottom
                    bottom=df['y1_label'],
                    label='Shuffling Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y3_label data
                    df['y3_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label and y2_label on the bottom
                    bottom=[i+j for i,j in zip(df['y1_label'],df['y2_label'])],
                    label='Shuffling Verif.',
                    # with alpha 0.6
                    alpha=0.6,
                    # with color
                    hatch='x',
                    color='#F4561D'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y4_label data
                    df['y4_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label on the bottom
                    bottom=[i+j+q for i,j,q in zip(df['y1_label'],df['y2_label'],df['y3_label'])],
                    label='DDT',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y5_label data
                    df['y5_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label on the bottom
                    bottom=[i+j+q+w for i,j,q,w in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'])],
                    label='DDT Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y6_label data
                    df['y6_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label on the bottom
                    bottom=[i+j+q+w+e for i,j,q,w,e in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'],df['y5_label'])],
                    label='DDT Verif.',
                    # with alpha 0.6
                    alpha=0.6,
                    # with color
                    hatch='x',
                    color='#3232FF'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y7_label data
                    df['y7_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label on the bottom
                    bottom=[i+j+q+w+e+r for i,j,q,w,e,r in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'],df['y5_label'],df['y6_label'])],
                    label='Collective Aggr.',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y8_label data
                    df['y8_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label on the bottom
                    bottom=[i+j+q+w+e+r+t for i,j,q,w,e,r,t in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'],df['y5_label'],df['y6_label'],df['y7_label'])],
                    label='Collective Aggr. Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y9_label data
                    df['y9_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label on the bottom
                    bottom=[i+j+q+w+e+r+t+z for i,j,q,w,e,r,t,z in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'],df['y5_label'],df['y6_label'],df['y7_label'],df['y8_label'])],
                    label='Collective Aggr. Verif.',
                    # with alpha 0.6
                    alpha=0.6,
                    # with color
                    hatch='x',
                    color='#8B4513'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y10_label data
                    df['y10_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label, y9_label on the bottom
                    bottom=[i+j+q+w+e+r+t+z+u for i,j,q,w,e,r,t,z,u in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'],df['y5_label'],df['y6_label'],df['y7_label'],df['y8_label'],df['y9_label'])],
                    label='Key Switching',
                    # with alpha 1
                    alpha=1,
                    # with color
                    color='#808080'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y11_label data
                    df['y11_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label, y9_label, y10_label on the bottom
                    bottom=[i+j+q+w+e+r+t+z+u+i for i,j,q,w,e,r,t,z,u,i in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'],df['y5_label'],df['y6_label'],df['y7_label'],df['y8_label'],df['y9_label'],df['y10_label'])],
                    label='Key Switching Proof',
                    # with alpha 0.8
                    alpha=0.8,
                    # with color
                    hatch='////',
                    color='#808080'))

# Create a bar plot, in position bar_l
bars.append(ax1.bar(bar_l,
                    # using the y12_label data
                    df['y12_label'],
                    # set the width
                    width=bar_width,
                    # with y1_label, y2_label, y3_label, y4_label, y5_label, y6_label, y7_label, y8_label, y9_label, y10_label, y11_label on the bottom
                    bottom=[i+j+q+w+e+r+t+z+u+i+o for i,j,q,w,e,r,t,z,u,i,o in zip(df['y1_label'],df['y2_label'],df['y3_label'],df['y4_label'],df['y5_label'],df['y6_label'],df['y7_label'],df['y8_label'],df['y9_label'],df['y10_label'],df['y11_label'])],
                    label='Key Switching Verif.',
                    # with alpha 0.6
                    alpha=0.6,
                    # with color
                    hatch='x',
                    color='#808080'))

# Set the x ticks with names
plt.xticks(tick_pos, df['x_label'],rotation='15')
ax1.yaxis.grid(True)

# Labelling
height=[0, 0, 0, 0, 0, 0]
for rects in bars:
    i=0
    for rect in rects:
        height[i]+=rect.get_height()
        i+=1


ax1.text(tick_pos[0] - 0.14, height[0] + 1, str(df['y_label'][0]), color='black', fontweight='bold')
ax1.text(tick_pos[1] - 0.10, height[1] + 1, str(df['y_label'][1]), color='black', fontweight='bold')
ax1.text(tick_pos[2] - 0.10, height[2] + 1, str(df['y_label'][2]), color='black', fontweight='bold')
ax1.text(tick_pos[3] - 0.10, height[3] + 1, str(df['y_label'][3]), color='black', fontweight='bold')
#ax1.text(tick_pos[4]-0.06,height[4]+1, str(df['y_label'][4]), color='black', fontweight='bold')
#ax1.text(tick_pos[5]-0.06,height[5]+1, str(df['y_label'][5]), color='black', fontweight='bold')

# Set the label and legends
ax1.set_ylabel("Runtime (s)", fontsize=22)
plt.legend(loc='upper right')

ax1.tick_params(axis='x', labelsize=24)
ax1.tick_params(axis='y', labelsize=24)

# Set a buffer around the edge
plt.xlim([min(tick_pos)-bar_width, max(tick_pos)+bar_width+0.2])

plt.savefig('secure_census.pdf', format='pdf')