import pydantic.error_wrappers

from avidtools.datamodels import report,enums,components
from pathlib import Path
import logging
import argparse
import json

def validate_reports(path:str):
    '''
    Validate reports via Pydantic

    '''
    folder = Path(path)

    if folder.is_dir():
        if folder.exists():
            logging.info('Processing folder...')
            for file in folder.glob('**/*.json'):
                logging.debug(file)

                # Load data
                with open(file) as f:
                    try:
                        datax = json.load(f)
                        report_obj = report.Report(**datax)
                    except pydantic.ValidationError as vae:
                        logging.error(f'File -> {file.as_posix()}')
                        logging.error(vae)
                    except pydantic.error_wrappers.ErrorWrapper as eo:
                        logging.error(eo)

        else:
            logging.error('Folder is missing')
    else:
        logging.error('Not a folder')

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-reports",default=False,action='store_true')
    parser.add_argument("-path", type=str, help="validate a folder")

    parser.add_argument("-v", "--verbosity", type=int,
                        help="increase output verbosity")

    args = parser.parse_args()

    if args.reports and args.path:
        validate_reports(args.path)


if __name__ == '__main__':
    main()





