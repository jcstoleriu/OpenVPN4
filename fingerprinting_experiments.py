import json, ack_algorithm, opcode_algorithm, csv, sys, tqdm, logging, os
from scapy.all import rdpcap, PcapReader
from utils import group_conversations
from openvpn_fingerprinting import print_summary

ALGORITHMS = {
    "opcode": opcode_algorithm.fingerprint_packets,
    "ack": ack_algorithm.fingerprint_packets
}

OUTPUT_CSV_HEADER = ["name", "file", "algorithm", "ip1", "port1", "ip2", "port2", "result"]


DEFAULT_CONFIG_PATH = "config.json"
DEFAULT_OUTPUT_FOLDER = "experiments"
PARAMS_KEY = "params"
MAX_FILE_SIZE_KEY = "max_file_size"

TEMP_FILE_EXTENSION = ".tmp"

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
    experiments = config["experiments"]
    output_folder = config.get("output_folder", DEFAULT_OUTPUT_FOLDER)
    os.makedirs(output_folder, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(os.path.join(output_folder, "experiments.log"), mode='a')
        ]
    )

    used_datasets = config["used_datasets"]
    for dataset_key in used_datasets:
        output_file_basename = os.path.join(output_folder, dataset_key)
        output_file = output_file_basename + ".csv"
        if os.path.exists(output_file):
            logging.info(f"Output file {output_file} already exists. Skipping it.")
            continue
        output_file = output_file + TEMP_FILE_EXTENSION

        if len(logging.getLogger().handlers) > 2:
            logging.getLogger().handlers.pop(2)
        logging.getLogger().addHandler(logging.FileHandler(f"{output_file_basename}.log", mode='w'))

        if not dataset_key in config_datasets:
            logging.error(f"dataset {dataset_key} not found in config. Skipping it.")
            continue
        for j, file in enumerate(config_datasets[dataset_key]):
            if not os.path.exists(file):
                logging.error(f"File {file} does not exist. Skipping it.")
                continue
            

            # give a limit for the max file size
            max_file_size = config[MAX_FILE_SIZE_KEY] if MAX_FILE_SIZE_KEY in config else float("inf")
            logging.info(f"Max file size is {max_file_size}")
            filesize = os.path.getsize(file)
            if filesize > max_file_size:
                logging.error(f"Skipping file {file}, due to large filesize {filesize} (limit {max_file_size})")
                continue

            with open(output_file, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile, delimiter=',',
                                    quotechar='|', quoting=csv.QUOTE_MINIMAL)
                csv_writer.writerow(OUTPUT_CSV_HEADER)

                # run all experiments
                logging.info(f"Fingerprinting file '{file}' ({j+1} of {len(config_datasets[dataset_key])} files)...")
                if not dry_run:
                    packets = PcapReader(file)
                    conversations, _ = group_conversations(packets, progressbar=True)

                for i, experiment in enumerate(experiments):
                    experiment_name = experiment["name"]
                    algorithm_type = experiment["algorithm"]
                    algorithm = ALGORITHMS[algorithm_type]
                    logging.info(f"Running experiment '{experiment_name}' with algorithm {algorithm_type} ({i+1} of {len(experiments)} experiments)")
                    
                    params = experiment.get(PARAMS_KEY, None)

                    if dry_run:
                        continue

                    results = algorithm(file, conversations=conversations, params=params, printer=lambda x : logging.info(x))

                    # print(f"Results for experiment {experiment['name']}")
                    # print(results)

                    for key, result in results.items():
                        csv_writer.writerow([experiment_name, file, algorithm_type, key[0][0], key[0][1], key[1][0], key[1][1], result])
        if os.path.exists(output_file):
            output_file_final = output_file.replace(TEMP_FILE_EXTENSION, "")
            os.rename(output_file, output_file_final)
            logging.info(f"output written to {output_file_final}")

if __name__ == "__main__":
    main(sys.argv)