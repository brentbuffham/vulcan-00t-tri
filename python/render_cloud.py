#!/usr/bin/env python3
"""Quick top-down render of a decoded XYZ cloud (X-Y scatter colored by Z) to PNG."""
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
xyz=sys.argv[1]; png=sys.argv[2]
P=np.loadtxt(xyz,delimiter=',')
# clip Z outliers for color scale
z=P[:,2]; zlo,zhi=np.percentile(z,2),np.percentile(z,98)
fig,ax=plt.subplots(1,2,figsize=(14,6))
sc=ax[0].scatter(P[:,0],P[:,1],c=np.clip(z,zlo,zhi),s=4,cmap='viridis')
ax[0].set_title(f'Top-down X-Y (n={len(P)})'); ax[0].set_xlabel('X'); ax[0].set_ylabel('Y'); ax[0].set_aspect('equal','datalim')
plt.colorbar(sc,ax=ax[0],label='Z')
ax[1].scatter(P[:,0],P[:,2],s=4,c='steelblue'); ax[1].set_title('Side X-Z'); ax[1].set_xlabel('X'); ax[1].set_ylabel('Z')
plt.tight_layout(); plt.savefig(png,dpi=90); print('wrote',png)
