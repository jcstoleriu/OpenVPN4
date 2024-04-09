# OpenVPN fingerprinting 

__Group 4__ - Leonard Eyer, Cristina Stoleriu, Sofia Lohr, Tobias Loch, Matthijs Reyers

----
This repository contains code for our report on the paper: _"OpenVPN is Open to VPN Fingerprinting"_ by Xue et al. (2022) [[1](#references)].

## Requirements
1. Install:
   - python 3.9
   - scapy 2.5.0
   - docker 24.0
2. Download the following datasets:
    - [VNAT](https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat)
    - [ISCXVPN2016](https://www.unb.ca/cic/datasets/vpn.html)


## Project structure
The project is structured as follows:

- [docker](./docker/): Docker environments to generate datasets with OpenVPN configurations (udp, tcp, udp-tls, tcp-tls)
- [docker-pcaps](./docker-pcaps/): Captured pcap files from the various Docker environments
- [pcap-dumps](./pcap-dumps/): Captured traffic from live OpenVPN connections
- [src](./src/): source code for the passive fingerprinting methods

## Running Experiments

1. Extract the contents of the [datasets](#requirements) into some folder
2. Adjust the paths in the [config](./config.json). 
3. Run the experiments by:
    ```shell
    python experiments.py
    ```
The [config](./config.json) contains the information on how to execute the experiments. Its structure is as follows:

- The `datasets` dictionary contains the path to all pcap files. The actual used datasets are specified in `used_datasets`
- The `experiments` array contains the algorithms that are run and with what parameters
- The `output_folder` field contains then the folder where for each dataset its results are output

## Docker environments

To generate some datasets with known OpenVPN configurations, we created several docker compose environments contained in the `docker` folder. 
The captured Pcap files are stored in the `docker-pcaps` folder.

Every OpenVPN client container runs the `docker/client.sh` script to generate some network traffic.


# References
1. Diwen Xue, Reethika Ramesh, Arham Jain, Michalis Kallitsis, J. Alex Halderman, Jedidiah R. Crandall, & Roya Ensafi (2022). OpenVPN is Open to VPN Fingerprinting. In 31st USENIX Security Symposium (USENIX Security 22) (pp. 483–500). USENIX Association.

