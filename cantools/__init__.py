import sys
import os
import argparse
import re
import binascii
import struct
import json
import shutil
from . import db

__author__ = 'Erik Moqvist'
__version__ = '16.2.0'


# Matches 'candump' output, i.e. "vcan0  1F0   [8]  00 00 00 00 00 00 1B C1".
RE_CANDUMP = re.compile(r'^.*  ([0-9A-F]+)   \[\d+\]\s*([0-9A-F ]*)$')

# (1378.006329)  can0   0B2   [8]  F9 0D 04 0E 0A 0E 11 0E
RE_TIMESTAMP = re.compile(r'\((.*)\)')

# signal database
signal_db = {}


def _mo_unpack(mo):
    frame_id = mo.group(1)
    frame_id = '0' * (8 - len(frame_id)) + frame_id
    frame_id = binascii.unhexlify(frame_id)
    frame_id = struct.unpack('>I', frame_id)[0]
    data = mo.group(2)
    data = data.replace(' ', '')
    data = binascii.unhexlify(data)

    return frame_id, data


def _format_message_json(dbf, frame_id, data):
    try:
        message = dbf.get_message_by_frame_id(frame_id)
    except KeyError:
        return 'Unknown frame id {}'.format(frame_id)

    try:
        decoded_signals_raw = message.decode(data, decode_choices=False, scaling=False)
        decoded_signals = message.decode(data, decode_choices=True, scaling=True)
    except ValueError as e:
        return str(e)

    formatted_signals = []

    for signal in message.signals:
        try:
            value_raw = decoded_signals_raw[signal.name]
            value = decoded_signals[signal.name]
        except KeyError:
            continue

        signal_dictionary = {
            "name": signal.name,
            "raw_value": value_raw,
            "computed_value": value
        }
        if signal.unit:
            signal_dictionary["unit"] = signal.unit

        formatted_signals.append(signal_dictionary)

    return {"id": frame_id, "name": message.name, "signals": formatted_signals}


def _signal_to_file(output_folder, timestamp, message_name, signals):
    # make message directories
    message_dir = os.path.join(output_folder, message_name)
    if not os.path.exists(message_dir):
        os.mkdir(message_dir)

    for signal in signals:
        if signal['name'] not in signal_db:
            signal_path = os.path.join(message_dir, signal['name'] + '.csv')
            if not os.path.exists(signal_path):
                with open(signal_path, "w") as sig_file:
                    sig_file.write("timestamp;raw_value;computed_value\n")
            signal_db[signal['name']] = {'message': message_name, 'values':[]}
        
        signal_db[signal['name']]['values'].append([timestamp, signal['raw_value'], signal['computed_value']])

        if len(signal_db[signal['name']]['values']) >= 512:
            signal_path = os.path.join(message_dir, signal['name'] + '.csv')
            with open(signal_path, "a") as sig_file:
                for sig in signal_db[signal['name']]['values']:
                    sig_file.write("{};{};{}\n".format(sig[0], sig[1], sig[2]))
            signal_db[signal['name']] = {'message': message_name, 'values':[]}


def _signal_flush(output_folder):
    for signal_name in signal_db:
        message_dir = os.path.join(output_folder, signal_db[signal_name]['message'])
        signal_path = os.path.join(message_dir, signal_name + '.csv')
        with open(signal_path, "a") as sig_file:
            for sig in signal_db[signal_name]['values']:
                sig_file.write("{};{};{}\n".format(sig[0], sig[1], sig[2]))


def _do_decode(args):
    dbf = db.load_file(args.dbfile)
    timestamp_only = args.timestamp_only
    silent_output = args.silent
    if args.output:
        output_folder = args.output[0]
        # re-create output folder
        if os.path.isdir(output_folder):
            shutil.rmtree(output_folder)
        os.makedirs(output_folder)
    else:
        output_folder = None
    
    first = True
    while True:
        line = sys.stdin.readline()

        # Break at EOF.
        if not line:
            if output_folder:
                _signal_flush(output_folder)
            break

        line = line.strip('\r\n')
        frame_dictionary = {
            "timestamp": line,
            "message": None
        }
        mo = RE_CANDUMP.match(line)
        ts = RE_TIMESTAMP.match(line)

        if ts:
            try:
                timestamp = float(ts.group(1))
            except ValueError:
                timestamp = 0
        else:
            timestamp = 0

        if mo:
            frame_id, data = _mo_unpack(mo)
            formatted_message = _format_message_json(
                dbf,
                frame_id,
                data
            )
            
            frame_dictionary = {
                "timestamp": timestamp if timestamp_only else line,
                "message": formatted_message
            }

        if not silent_output:
            if first:
                print("[{}".format(json.dumps(frame_dictionary, ensure_ascii=False)))
                first = False
            else:
                print(",{}".format(json.dumps(frame_dictionary, ensure_ascii=False)))
        
        if output_folder and "name" in frame_dictionary["message"]:
            _signal_to_file(
                output_folder,
                timestamp,
                frame_dictionary["message"]["name"],
                frame_dictionary["message"]["signals"]
            )

    if not silent_output:
        print(']')


def _main():
    parser = argparse.ArgumentParser(
        description='Various CAN utilities.')

    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('--version',
                        action='version',
                        version=__version__,
                        help='Print version information and exit.')

    # Workaround to make the subparser required in Python 3.
    subparsers = parser.add_subparsers(title='subcommands',
                                       dest='subcommand')
    subparsers.required = True

    # The 'decode' subparser.
    decode_parser = subparsers.add_parser(
        'decode',
        description=('Decode "candump" CAN frames read from standard input '
                     'and print them in a human readable format.'))
    decode_parser.add_argument('-t', '--timestamp-only',
                               action='store_true',
                               help='Display only timestamp in header.')
    decode_parser.add_argument('-s', '--silent',
                               action='store_true',
                               help='Do not display JSON output.')
    decode_parser.add_argument('-o', '--output',
                               nargs='+',
                               help='Output folder for signal .csv files.')
    decode_parser.add_argument('dbfile', help='Database file (.dbc).')
    decode_parser.set_defaults(func=_do_decode)

    args = parser.parse_args()

    if args.debug:
        args.func(args)
    else:
        try:
            args.func(args)
        except BaseException as e:
            sys.exit(str(e))
