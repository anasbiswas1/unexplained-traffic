# unexplained-traffic

**Unexplained Traffic: Detecting Compromised AI Agents by Reconciling Encrypted Flows with Trusted Execution Logs**

Author: Md Anas Biswas · University of Portsmouth

A monitor for AI agents that asks whether every byte an agent sends can be explained by an action a trusted
controller recorded, instead of asking whether the traffic looks malicious. It reads encrypted traffic metadata only:
packet sizes, timing, direction and destination names.

## Layout
- `notebooks/` numbered experiment notebooks; each runs its experiment through `src/` and ends with the standard commit cell
- `src/` modules the notebooks import
- `tools/commit_cell.py` the single commit step
- `reports/` result tables and `RESULTS_LOG.md`
- `figures/` generated figures
- `data/` captures, extracted tables and caches; kept on Drive, never committed

## Data
ANT agent network traffic dataset (Li et al., arXiv:2610.06514), https://huggingface.co/datasets/benzenenene/ANT,
released under CC BY 4.0.

## Status
- [x] 00 project setup
- [ ] 01 ANT benign floor and go/no-go gate
