# coding: utf-8

import os
import sqlite3
import sys
import time
from argparse import ArgumentParser
from dataset.builder import generate_legit_binaries_dataset, generate_malwares_dataset, SQLITE_SCHEME, import_lisa_reports, export_dataset_to_csv


if __name__ == "__main__":
    parser = ArgumentParser(prog="python -m dataset", description='This is the dataset builder.')
    parser.add_argument('--malware-dirs', metavar="DIRECTORY", nargs='+',
                        help='directories of malwares to process')
    parser.add_argument('--legit-dirs', metavar="DIRECTORY", nargs='+',
                        help='directories of legit binaries to process')
    parser.add_argument("--db", metavar="DB_FILE", required=True,
                        help="sqlite database")
    parser.add_argument("--overwrite", action="store_true",
                        help="delete the existing database to create a new one")
    parser.add_argument("--append", action="store_true",
                        help="append results to the existing database")
    parser.add_argument("--stats", action="store_true",
                        help="prints some stats about the given dataset")
    parser.add_argument("--lisa-reports-dir", metavar="REPORTS_DIR",
                        help="parses json reports in the directory and insert results in the database")
    parser.add_argument('--export-csv', action="store_true", 
                        help='export dataset to csv file')

    args = parser.parse_args(None if sys.argv[1:] else ['--help'])

    if args.stats is None and args.legit_dirs is None and args.malware_dirs is None and args.lisa_reports_dir is None:
        parser.error("nothing to do")

    if os.path.isfile(args.db) and not args.export_csv:
        if args.overwrite:
            os.remove(args.db)
            print("Previous database overwritten")

        elif args.append:
            print("Appending data to existing database")

        elif not args.stats:
            parser.error(args.db + " already exists, you must specify --append or --overwrite")

    else:
        if args.append:
            parser.error("cannot append to " + args.db + " because it does not exist (try removing --append)")

    legits = args.legit_dirs
    malwares = args.malware_dirs
    lisa_reports_dir = args.lisa_reports_dir
    export_csv = args.export_csv

    db = sqlite3.connect(args.db)

    if not args.append:
        db.executescript(SQLITE_SCHEME)
        db.commit()

    if legits:
        begin_analysis = time.time()
        generate_legit_binaries_dataset(legits, db)

        print("\n" + "-" * 50)
        print("Legit binaries analysis done in", int(time.time() - begin_analysis), "seconds")

    if malwares:
        begin_analysis = time.time()
        generate_malwares_dataset(malwares, db)

        print("\n" + "-" * 50)
        print("Malwares analysis done in", int(time.time() - begin_analysis), "seconds")

    if lisa_reports_dir:
        begin_analysis = time.time()
        import_lisa_reports(lisa_reports_dir, db)

        print("\n" + "-" * 50)
        print("Reports import done in", int(time.time() - begin_analysis), "seconds")

    if args.stats:
        print("-" * 50)

        cursor = db.execute("SELECT COUNT(*) FROM executions;")
        executions_count = cursor.fetchone()[0]
        print("Executions count:", executions_count)

        cursor = db.execute("SELECT COUNT(*) FROM flows;")
        flows_count = cursor.fetchone()[0]
        print("Flows count:", flows_count)

        cursor = db.execute("SELECT COUNT(*) FROM syscalls;")
        syscalls_count = cursor.fetchone()[0]
        print("Syscalls count:", syscalls_count)
        print("-" * 50)

    if export_csv:
        export_dataset_to_csv(args.db)
        
    db.close()
