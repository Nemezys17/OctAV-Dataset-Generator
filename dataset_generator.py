# coding: utf-8

from sandbox.api import analyse_malware, analyse_legit_binary


def generate_legit_binaries_dataset():
    print("Generating legit binaries dataset...")

    # TODO : Iterate through the files to send to the sandbox
    # with multiprocessing.Pool(processes=4) as pool:  ??
    #analyse_legit_binary("/bin/ls")


def generate_malwares_dataset():
    print("Generating malwares dataset...")

    # TODO : Iterate through the files to send to the sandbox
    # with multiprocessing.Pool(processes=4) as pool:  ??
    analyse_malware("/bin/ls")


if __name__ == "__main__":
    generate_legit_binaries_dataset()
    generate_malwares_dataset()
