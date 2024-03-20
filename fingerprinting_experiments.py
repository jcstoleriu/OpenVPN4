import json, ack_algorithm, opcode_algorithm, csv, sys, tqdm
from scapy.all import rdpcap
from utils import group_conversations

ALGORITHMS = {
    "opcode": opcode_algorithm.fingerprint_packets,
    "ack": ack_algorithm.fingerprint_packets
}

OUTPUT_CSV_HEADER = ["file", "algorithm", "ip1", "port1", "ip2", "port2", "result"]


DEFAULT_CONFIG_PATH = "config.json"
PARAMS_KEY = "params"

def main(argv):
    config_path = DEFAULT_CONFIG_PATH
    with open(config_path, "r") as config_file:
        config = json.load(config_file)

    with open(config["output"], 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile, delimiter=',',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
        csv_writer.writerow(OUTPUT_CSV_HEADER)

        
        experiments = config["experiments"]
        # run all experiments
        for experiment in experiments:
            files = experiment["files"]

            print(f"Running experiment {experiment['name']}")
            for file in tqdm.tqdm(files):
                algorithm_type = experiment["algorithm"]
                algorithm = ALGORITHMS[algorithm_type]
                params = experiment.get(PARAMS_KEY, None)
                results = algorithm(file, params=params)

                # print(f"Results for experiment {experiment['name']}")
                # print(results)

                for key, result in results.items():
                    csv_writer.writerow([file, algorithm_type, key[0][0], key[0][1], key[1][0], key[1][1], result])
    

if __name__ == "__main__":
    main(sys.argv)