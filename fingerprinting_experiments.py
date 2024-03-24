import json, ack_algorithm, opcode_algorithm, csv, sys, tqdm, logging, os
from scapy.all import rdpcap
from utils import group_conversations
from openvpn_fingerprinting import print_summary

ALGORITHMS = {
    "opcode": opcode_algorithm.fingerprint_packets,
    "ack": ack_algorithm.fingerprint_packets
}

OUTPUT_CSV_HEADER = ["name", "file", "algorithm", "ip1", "port1", "ip2", "port2", "result"]


DEFAULT_CONFIG_PATH = "config.json"
DEFAULT_OUTPUT_FILE = "output.csv"
PARAMS_KEY = "params"
MAX_FILE_SIZE_KEY = "max_file_size"

def main(argv:list):
    config_path = DEFAULT_CONFIG_PATH
    dry_run = False

    if "-d" in argv:
        dry_run = True
        argv.remove("-d")

    if len(argv) > 1:
        config_path = argv[1]

    with open(config_path, "r") as config_file:
        config = json.load(config_file)

    # parse datasets
    config_datasets = config["datasets"]

    output_file = config.get("output", DEFAULT_OUTPUT_FILE)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(os.path.splitext(output_file)[0] + ".log", mode='w'),
            logging.StreamHandler(sys.stdout)
        ]
    )

        # give a limit for the max file size
    max_file_size = config[MAX_FILE_SIZE_KEY] if MAX_FILE_SIZE_KEY in config else float("inf")
    logging.info(f"Max file size is {max_file_size}")

    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile, delimiter=',',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(OUTPUT_CSV_HEADER)

        
        experiments = config["experiments"]
        # run all experiments
        for i, experiment in enumerate(experiments):
            experiment_dataset_keys = experiment["datasets"]
            
            experiment_name = experiment["name"]
            algorithm_type = experiment["algorithm"]
            algorithm = ALGORITHMS[algorithm_type]
            logging.info(f"Running experiment '{experiment_name}' with algorithm {algorithm_type} ({i+1} of {len(experiments)} experiments)")

            experiment_datasets = []
            for experiment_dataset_key in experiment_dataset_keys:
                if experiment_dataset_key in config_datasets:
                    experiment_datasets += config_datasets[experiment_dataset_key]
                else:
                    logging.error(f"dataset {experiment_dataset_key} not found in config. Skipping it.")

            for j, file in enumerate(experiment_datasets):
                if not os.path.exists(file):
                    logging.error(f"File {file} does not exist. Skipping it.")
                    continue
                filesize = os.path.getsize(file)
                if filesize > max_file_size:
                    logging.error(f"Skipping file {file}, due to large filesize {filesize} (limit {max_file_size})")
                    continue
                logging.info(f"Fingerprinting file '{file}' ({j+1} of {len(experiment_datasets)} files)...")
                
                params = experiment.get(PARAMS_KEY, None)

                if dry_run:
                    continue

                results = algorithm(file, params=params, printer=lambda x : logging.info(x))

                # print(f"Results for experiment {experiment['name']}")
                # print(results)

                for key, result in results.items():
                    csv_writer.writerow([experiment_name, file, algorithm_type, key[0][0], key[0][1], key[1][0], key[1][1], result])
    logging.info(f"output written to {output_file}")

if __name__ == "__main__":
    main(sys.argv)