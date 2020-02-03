# coding: utf-8

import json
import os
import sqlite3
import threading
import time
import subprocess

from multiprocessing.pool import ThreadPool
from typing import List

from dataset.core import Execution
from sandbox import legit, malware
from sandbox.malware import parse_lisa_report

SQLITE_SCHEME = """
                CREATE TABLE IF NOT EXISTS executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_line TEXT NOT NULL UNIQUE, -- The same binary can appear multiple times with different parameters
                    is_malware BOOL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS flows (
                    id integer PRIMARY KEY AUTOINCREMENT,
                    execution_id INTEGER,
                    FOREIGN KEY(execution_id) REFERENCES executions(id)
                    -- Maybe later we could add stuff like "opened_files"
                );

                CREATE TABLE IF NOT EXISTS syscalls (
                    id integer PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER,
                    name TEXT NOT NULL,
                    parameters TEXT,
                    return_value TEXT,
                    -- exec_timestamp INTEGER,
                    FOREIGN KEY(flow_id) REFERENCES flows(id)
                );
                """

# We use a list to buffered executions for performance
buffered_executions = []  # type: List[Execution]

# The higher this value is, the heavier it will be on RAM usage. It will increase speed however
MAX_CACHED_EXECUTIONS = 100

cleaning_lock = threading.Lock()
needs_cleaning_cond = threading.Condition(lock=cleaning_lock)

analysis_pool_results = []


def _cleaning_work(db):

    results_to_remove = []

    for r in analysis_pool_results:
        if r.ready():
            results_to_remove.append(r)

    for r in results_to_remove:
        analysis_pool_results.remove(r)

    if len(buffered_executions) > MAX_CACHED_EXECUTIONS:
        _export_buffered_binaries(db)


def _error_callback(exc):
    raise exc


# TODO : compare sqlite vs postgresql performance
def _export_buffered_binaries(db: sqlite3.Connection):

    to_remove_from_cache = []

    for execution in buffered_executions:

        try:
            cursor = db.execute("INSERT INTO executions VALUES(NULL, ?, ?);",
                                (execution.command_line, execution.is_malware))

            binary_id = cursor.lastrowid

            execution_sorted_by_pid = sorted(execution, key=lambda f: f.pid)

            # data inserted follows the spawned processes order (thanks to pid sorting)
            for flow in execution_sorted_by_pid:
                cursor = db.execute("INSERT INTO flows VALUES(NULL, ?);", (binary_id,))

                flow_id = cursor.lastrowid

                for syscall in flow:
                    db.execute(f"INSERT INTO syscalls VALUES(NULL, ?, ?, ?, ?);",
                               (flow_id, syscall.name, syscall.raw_parameters, syscall.return_value))

            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()

        to_remove_from_cache.append(execution)

    for execution in to_remove_from_cache:
        buffered_executions.remove(execution)


# This callback is called in the context of the main process
def _binary_analysis_finished_callback(execution: Execution):

    if execution:
        print("command '{}' started {} process(es) for a total of {} syscalls".format(
            execution.command_line,
            len(execution),
            sum(len(flow) for flow in execution))
        )

        buffered_executions.append(execution)


def _get_files_already_in_dataset(db: sqlite3.Connection):
    # We dont want command line duplicates in the dataset
    cursor = db.execute("SELECT command_line FROM executions;")
    return set(item[0] for item in cursor.fetchall())


def _generate_dataset(module, directories: List[str], db: sqlite3.Connection):
    """
    module: either 'malware' or 'legit'
    directories: the directories to get the executables from
    """

    global analysis_pool_results

    if not legit.check_requirements():
        print("Cannot continue legit binaries analysis")
        exit(1)

    binaries = set()
    for bin_dir in directories:
        for file in os.listdir(bin_dir):
            full_path = os.path.realpath(bin_dir + "/" + file)
            if os.path.isfile(full_path):
                binaries.add(full_path)

    binaries = sorted(list(binaries))  # Sort in order to see progress based on alphabetical names
    commands_already_in_dataset = _get_files_already_in_dataset(db)

    with ThreadPool(processes=os.cpu_count() * 2) as pool:

        for binary in binaries:

            # Skip binaries we already have
            if binary in commands_already_in_dataset:
                continue

            generated_commands = module.generate_command_lines_from_binary(binary)

            for cmd in generated_commands:
                result = pool.apply_async(module.analyse, args=(cmd,),
                                          callback=_binary_analysis_finished_callback,
                                          error_callback=_error_callback)
                analysis_pool_results.append(result)

            _cleaning_work(db)

        commands_already_in_dataset.clear()  # free some memory

        while analysis_pool_results:
            _cleaning_work(db)

            if analysis_pool_results:
                time.sleep(3)

    _export_buffered_binaries(db)  # Export remaining buffered flows


def generate_legit_binaries_dataset(legit_directories: List[str], db: sqlite3.Connection):
    print("Generating legit binaries dataset...")
    _generate_dataset(legit, legit_directories, db)


def generate_malwares_dataset(malware_directories: List[str], db: sqlite3.Connection):
    print("Generating malwares dataset...")
    _generate_dataset(malware, malware_directories, db)


def import_lisa_reports(reports_dir, db: sqlite3.Connection):
    global analysis_pool_results

    commands_already_in_dataset = _get_files_already_in_dataset(db)

    with ThreadPool(processes=os.cpu_count()) as pool:

        for file in os.listdir(reports_dir):
            with open(reports_dir + "/" + file, "r") as fd:
                content = fd.read()

            report = json.loads(content)

            # Skip binaries we already have
            if report["file_name"] in commands_already_in_dataset:
                continue

            result = pool.apply_async(parse_lisa_report, args=(report,),
                                      callback=_binary_analysis_finished_callback,
                                      error_callback=_error_callback)
            analysis_pool_results.append(result)

            _cleaning_work(db)

        commands_already_in_dataset.clear()  # free some memory

        while analysis_pool_results:
            _cleaning_work(db)

            if analysis_pool_results:
                time.sleep(3)

        _export_buffered_binaries(db)  # Export remaining buffered flows


def export_dataset_to_csv(db_filename):
    print("Exporting malwares dataset to CSV...")
    
    try:
        subprocess.run(f"sqlite3 -header -csv {db_filename} \"SELECT * FROM executions\" > dataset_executions.csv", shell=True, check=True)
        subprocess.run(f"sqlite3 -header -csv {db_filename} \"SELECT * FROM flows\" > dataset_flows.csv", shell=True, check=True)
        subprocess.run(f"sqlite3 -header -csv {db_filename} \"SELECT * FROM syscalls\" > dataset_syscalls.csv", shell=True, check=True)

        #Load legits reports and compute max_sequence_length and max_sequences_number
        with open("dataset_executions.csv", "r") as executions_file:
            executions = executions_file.read().splitlines()

        with open("dataset_flows.csv", "r") as flows_file:
            flows = flows_file.read().splitlines()

        syscall_file = open("dataset_syscalls.csv", "r")
        flow_id = 1
        syscall_file.readline()

        for execution in executions[1:]:
            execution_trace = []
            for flow in flows[flow_id:]:
                flow_sequences = []
                if flow.split(',')[1] == execution.split(',')[0]:
                    line = syscall_file.readline().splitlines()
                    while line != [] and line[0].split(',')[1] == flow.split(',')[0]:
                        fields = line[0].split(',')
                        try:
                            flow_sequences.append(SYSCALLS[fields[2]])
                        except:
                            pass
                        line = syscall_file.readline().splitlines()
                    execution_trace.append(flow_sequences)
                else:
                    flow_id = int(flow.split(',')[0]) 
                    break

            with open("dataset.csv", "a") as dataset_file:
                dataset_file.write("0")
                for sequence in execution_trace:
                    data = ','.join([str(syscall) for syscall in sequence])
                    dataset_file.write(",\"{}\"".format(data))
                dataset_file.write("\n")

        #Load malwares reports and compute max_sequence_length and max_sequences_number
        for filename in os.listdir(MALWARES_REPORTS_DIR):
            syscalls_sequences = _load_json_report("{}/{}".format(MALWARES_REPORTS_DIR, filename))

            with open("dataset.csv", "a") as dataset_file:
                dataset_file.write("1")
                for sequence in list(syscalls_sequences.values()):
                    data = ','.join([str(syscall) for syscall in sequence])
                    dataset_file.write(",\"{}\"".format(data))
                dataset_file.write("\n")
                
        os.remove("dataset_executions.csv")
        os.remove("dataset_flows.csv")
        os.remove("dataset_syscalls.csv")
    except Exception as e:
        print("Dataset export failed")
        print(e)