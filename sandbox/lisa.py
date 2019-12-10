# coding: utf-8

import requests
import os
import time

LISA_SANDBOX_URL = "http://localhost:4242"


class SandBoxException(Exception):
    pass


def _send_file_to_lisa(filename):
    resp = requests.post(
        LISA_SANDBOX_URL + "/api/tasks/create/file",
        files={"file": (os.path.basename(filename), open(filename, "rb"))},
        data={"exec_time": "10"}
    )

    if resp.status_code != 200:
        raise SandBoxException("the sandbox returned HTTP code " + str(resp.status_code))

    task_id = resp.json()["task_id"]
    print("Task ID:", task_id)

    while True:

        resp = requests.get(LISA_SANDBOX_URL + "/api/report/" + task_id)

        if resp.status_code == 200:
            break

        if resp.status_code != 404:
            raise SandBoxException(f"the sandbox returned HTTP code {resp.status_code} during report waiting")

        print("Waiting for the report...")
        time.sleep(2)

    print(resp.json())
    print("\nGOT THE REPORT !!!")


def analyse(binary_path):

    if not os.path.isfile(binary_path):
        raise Exception(f"{binary_path} does not exist")

    _send_file_to_lisa(binary_path)