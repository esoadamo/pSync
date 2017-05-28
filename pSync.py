"""
Copyright 2016 Adam Hlaváček

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
"""
import hashlib
import os.path
import sys
import shutil
import sqlite3
import time

version = 0.8


def main():
    if Params.param_exists('-V'):
        print('pSync v%s' % version)
        exit(0)

    if len(Params.sys_args) == 0 or Params.param_exists("-help") or Params.param_exists("-h") \
            or Params.param_exists("/?") or Params.get_param('-d') is None:
        print("Usage: " + sys.argv[0] + " -d source_directory [-t target_directory] [-a algorithm] [-c]"
                                        " [-s hash file] [-r] [-v] [-V] [--no-sql [--allow-rename]] "
                                        "[--abs] [--no-info]")
        print("-s where to save hashes")
        print("-t where to move modified file")
        print("-a algorithm to use, default SHA256. Available: sha512 (super-secure), sha256 (default), "
              "sha1 (good-enough for home data), md5 (fastest)")
        print("-c wait for confirmation before copying files")
        print("-v verbose")
        print("-V prints version and exits")
        print("--no-sql do NOT use sql database instead of txt file (saves disk usage)")
        print('--allow-rename passing this will cause no-sql mode to look for renamed files. Can take very long time')
        print("--abs save file absolute paths of the files in database")
        print("--no-info prints just list of modified files")
        exit(0)

    """
    When we are here, it means we have:
    -d parameter that points us to the source directory
    """
    time_start = int(round(time.time() * 1000))  # Time when this script started. Saved in SQL database

    source_dir = Params.get_param("-d")  # Path to the directory that is hashed
    # For better formatting make sure that this directory path is complete
    if source_dir is not None and not source_dir.endswith(os.sep):
        source_dir += os.sep

    relative_file_names = not Params.param_exists("--abs")  # Shall we save absolute file paths in database?
    verbose = Params.param_exists('-v')  # When true prints really much output about progress
    target_dir = Params.get_param('-t')  # If set, modified files will be copied into this directory
    wait_for_confirmation = Params.param_exists('-c')  # If set, ask user before actions like coping
    use_sql = not Params.param_exists("--no-sql")  # Use plaintext vs sql database format
    list_only = Params.param_exists("--no-info")  # Do not print info about how many files were listed etc
    no_sql_allow_rename = Params.param_exists("--allow-rename")

    # For better formatting make sure that this directory path is complete
    if target_dir is not None and not target_dir.endswith(os.sep):
        target_dir += os.sep

    # Select right path for the file with hashes
    if Params.param_exists("-s"):
        save_hash_file_path = Params.get_param("-s")
    else:
        save_hash_file_path = get_file_name(source_dir) + "_hash"
        if use_sql:
            save_hash_file_path += ".db"
        else:
            save_hash_file_path += ".txt"
    # When not using SQL mode, better save new hashes into another temp file, not overwriting current hashes
    # Otherwise old hashes can be lost on process terminating
    save_hash_file_path_tmp = save_hash_file_path + "_tmp"

    # Select algorithm, default is sha256
    algorithm = Params.get_param('-a')
    if algorithm is None:
        algorithm = 'sha256'

    # If file with hashes already exists, load them and check if they changed
    mode_check = os.path.isfile(save_hash_file_path)

    modified_files = []  # List with paths to modified files
    deleted_files = []  # List with paths to deleted file
    new_files = []  # List of new files
    renamed_hashes = []  # List of hashes that have been renamed
    renamed_files = {}  # Keys are files before renaming, values are their new names
    no_modifications = True  # False when any file is added/changed/deleted

    hash_file_writer = None  # In clear text mode this is writer to temp file where hashes are stored

    # Create SQL connection
    if use_sql:
        sql_conn = sqlite3.connect(save_hash_file_path)
        sql = sql_conn.cursor()
    else:
        sql_conn = sql = None

    # Load hashes from database/data file
    if mode_check:
        if not list_only:
            print('Loading saved hashes')
        hashes = {}  # Dictionary with hashes - key is file path, value is file hash
        if use_sql:
            sql.execute("UPDATE hashes SET found=0")
            if not list_only:
                print('%d hashes loaded' % sql.execute("SELECT COUNT(*) FROM hashes").fetchone()[0])
        else:
            with open(save_hash_file_path, 'rt') as f:
                hashes_txt = f.read().split('\n')
            for line in hashes_txt:
                if len(line) == 0:
                    continue
                split = line.split(" ", 1)
                if len(split) == 2:
                    hashes[split[1]] = split[0]
                else:
                    if not list_only:
                        print('Wrong formatted line ' + line)
            hash_file_writer = open(save_hash_file_path_tmp, 'wt')  # Better not overwrite already saved hashes
            if not list_only:
                print('%d hashes loaded' % len(hashes))

    # Not checking -> first run -> create new database/data file
    else:
        if use_sql:
            sql.execute('CREATE TABLE "hashes" ( `file` TEXT NOT NULL UNIQUE, `hash` TEXT NOT NULL,'
                        ' `modified` INTEGER NOT NULL DEFAULT 0, `found` INTEGER NOT NULL DEFAULT 1 )')
        else:
            hash_file_writer = open(save_hash_file_path, 'wt')  # Better not overwrite already saved hashes

    # List all files (not directories) that will be hashed
    if not list_only:
        print('Listing directory')
    files = list_files(source_dir, directories=False)

    if files is None:
        print(source_dir + " is not a valid file/directory.")
        exit(1)

    if not list_only:
            print('Found %d files' % len(files))
    for file_index, file in enumerate(files):
        if not os.path.isfile(file):
            # If file does not exist, but during listing did, it was deleted during hashing process
            deleted_files.append(file)
            continue
        file_hash = get_file_hash(file, algorithm)
        if file_hash is None:
            print('Unknown algorithm "%s"' % algorithm)
            exit(0)

        if relative_file_names:
            file = file[len(source_dir):]  # Strip source directory path from the file path

        line = file

        if not use_sql:
            hash_file_writer.write(file_hash + " " + file + "\n")

        force_verbose = False
        if mode_check:
            file_already_hashed = False
            database_hash = None
            if use_sql:
                sql_result = sql.execute("SELECT hash FROM hashes WHERE file=?", (file,)).fetchone()
                if sql_result is not None and len(sql_result) > 0:
                    file_already_hashed = True
                    database_hash = sql_result[0]
                del sql_result
            else:
                for database_file, database_hash in hashes.items():
                    if database_file == file:
                        file_already_hashed = True
                        break
            if file_already_hashed:
                if file_hash == database_hash:
                    line = 'OK ' + line
                    if use_sql:
                        sql.execute("UPDATE hashes SET found=1 "
                                    "WHERE file=?", (file,))
                else:
                    force_verbose = True
                    no_modifications = False
                    line = 'MODIFIED ' + line
                    modified_files.append(file)
                    if use_sql:
                        sql.execute("UPDATE hashes SET hash=?, modified=?, found=1 "
                                    "WHERE file=?", (file_hash, time_start, file))
                if not use_sql:
                    hashes.pop(file, None)  # Delete this hash from memory when found
            else:
                # File appears to be new, but we will check if it is not just renamed (if we have it already hashed)
                file_is_renamed = False  # Can be False or name of file before renaming
                if use_sql:
                    sql_result = sql.execute("SELECT file FROM hashes WHERE hash=?", (file_hash,)).fetchone()
                    if sql_result is not None and len(sql_result) == 1 and file_hash not in renamed_hashes:
                        # When we have more than 1 file with same hash it database it means that we have multiple copies
                        # of the same file. Therefore cannot we say which of them was renamed.
                        file_is_renamed = sql_result[0]
                        renamed_hashes.append(file_hash)
                        sql.execute("UPDATE hashes SET file=?, modified=?, found=1 "
                                    "WHERE file=?", (file, time_start, file_is_renamed))
                else:
                    really_do_not_care_about_time_i_spend_computing = no_sql_allow_rename
                    # When True, we have to go through WHOLE database for EVERY single file
                    if really_do_not_care_about_time_i_spend_computing and file_hash not in renamed_hashes:
                        files_with_same_hashes_count = 0
                        file_is_renamed_temp = None
                        for database_file, database_hash in hashes.items():
                            if database_hash == file_hash:
                                file_is_renamed_temp = database_file
                                files_with_same_hashes_count += 1
                        if files_with_same_hashes_count == 1:
                            # When we have more than 1 file with same hash it database it means that we have
                            #  multiple copies of the same file. Therefore cannot we say which of them was renamed.
                            file_is_renamed = file_is_renamed_temp
                        del file_is_renamed_temp
                    # End of if really_do_not_care_about_time_i_spend_computing:
                if not file_is_renamed:
                    line = 'NEW ' + line
                    no_modifications = False
                    force_verbose = True
                    new_files.append(file)
                    if use_sql:
                        sql.execute("INSERT INTO hashes VALUES (?, ?, ?, 1)", (file, file_hash, time_start))
                else:  # File is renamed
                    force_verbose = True
                    line = 'RENAMED %s to ' % file_is_renamed + line
                    no_modifications = False
                    renamed_files[file_is_renamed] = file  # Key is name before renaming, value is new name

        else:
            line = 'INDEXED ' + line
            new_files.append(file)
            if use_sql:
                sql.execute("INSERT INTO hashes VALUES (?, ?, ?, 1)", (file, file_hash, time_start))
        verbose_bck = False
        if force_verbose:
            verbose_bck, verbose = verbose, force_verbose
        if verbose:
            print(line)
        if force_verbose:
            verbose = verbose_bck
    """
    All hashing was completed
    """

    # Get files that was not found on system, but exists in database (this files were deleted)
    if use_sql:
        sql_result = sql.execute("SELECT file FROM hashes WHERE found=0").fetchall()
        for sql_row in sql_result:
            hashes[sql_row[0]] = None
        del sql_result
        sql.execute("DELETE FROM hashes WHERE found=0")

    """
    Save databases and show info to user
    """
    if use_sql:
        sql_conn.commit()
        sql_conn.close()
    else:
        hash_file_writer.close()

    if mode_check:
        # All files inside hashes dict were not found on the disk, so they had to be deleted
        for deleted_file, hash_value in hashes.items():
            no_modifications = False
            print('DELETED ' + deleted_file)
            deleted_files.append(deleted_file)
        if no_modifications:
            print('No modifications made')
        else:
            if not list_only:
                print('%d files added, %d changed, deleted %d, renamed %d' % (len(new_files), len(modified_files),
                                                                              len(deleted_files), len(renamed_files)))

        if not use_sql:  # Move clear text tmp file and overwrite persistent hashes file
            shutil.move(save_hash_file_path_tmp, save_hash_file_path)
    else:
        if not list_only:
            print('First indexing completed')
    """
    Saving info about this session done
    """

    """
    If enabled, copy modified files to new location
    """
    if len(modified_files) + len(new_files) + len(deleted_files) > 0 and target_dir is not None:
        modified_files.extend(new_files)  # All modified files are copied, so copy all new files too

        if wait_for_confirmation:
            if not input_yes_no("Do you want to copy modified and delete removed files?"):
                print('Ok, by then')
                exit(0)
            if not list_only:
                    print('Copying changed files')
        for file in modified_files:
            source_file = source_dir + file
            target_file = target_dir + file
            target_file_dir = os.path.dirname(target_file)
            if not os.path.isfile(source_file):
                continue
            if not os.path.isdir(target_file_dir):
                if verbose:
                    print('Creating directory "%s"' % target_file_dir)
                os.makedirs(target_file_dir)
            if verbose:
                print('Copying "%s" to "%s"' % (source_file, target_file))
            shutil.copy(source_file, target_file)

        # Delete removed files from backup
        if len(deleted_files) > 0 and target_dir is not None:
            print('Deleting removed files')
            for file in deleted_files:
                target_file = target_dir + file
                if not os.path.isfile(target_file):
                    continue
                if verbose:
                    print('Deleting "%s"' % target_file)
                os.remove(target_file)
    # TODO Implement renaming
    """
    Updating backup done
    """
    if not list_only:
        print('Done')


def list_files(directory, relative=False, files=True, directories=True):
    """Lists all files in directory and subdirectories in absolute path form.
    :param directory directory to be listed
    :param relative if set to true, does return only relative path to the file, based on source folder
    :param files if set to False, only directories are listed
    :param directories if set to False, only files are listed
    :return if :param directory is directory - list of all files and directories in subdirectories
    :return if :param directory is file - list which contains only this file
    :return otherwise None"""
    import os
    if not relative:
        directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        if os.path.isfile(directory):
            return [directory]
        return None
    listed_files = []
    for file in os.listdir(directory):
        file_path = directory + os.sep + file
        if os.path.isdir(file_path):
            listed_files.extend(list_files(file_path, relative, files, directories))
            if directories:
                listed_files.append(file_path)
        elif files:
            listed_files.append(file_path)
    return listed_files


def get_file_name(path):
    """Parses filename from path"""
    head, tail = os.path.split(path)
    return tail or os.path.basename(head)


def get_file_hash(file, algorithm):
    """
    Hashes file and returns its hash
    :param file: file to be hashed
    :param algorithm: algorithm used for hashing
    :return: hash of the file or None when file does not exists or None when wrong algorithm is used
    """
    if not os.path.isfile(file):
        return None
    if algorithm == 'sha256':
        hash_function = hashlib.sha256()
    elif algorithm == 'sha1':
        hash_function = hashlib.sha1()
    elif algorithm == 'md5':
        hash_function = hashlib.md5()
    elif algorithm == 'sha512':
        hash_function = hashlib.sha512()
    else:
        return None

    file_reader = open(file, 'rb')
    while True:
        file_bytes = file_reader.read(16 * 1024 * 1024)
        if not file_bytes:
            break
        hash_function.update(file_bytes)
    del file_bytes
    file_reader.close()
    file_hash = hash_function.hexdigest()
    return file_hash


def input_yes_no(question, default="NONE"):
    """Asks user standard yes/no question that can be answered y (yes) or n (no)
    :param question: question showed to user
    :param default:  action to do when user does not input nothing. By default "NONE", can be also "YES" or "NO"
    :return: True if final respond is yes, False if final respond is No
    """
    default_return = None
    if default.upper() == "YES":
        question += " Y/n "
        default_return = True
    elif default.upper() == "NO":
        question += " y/N "
        default_return = False
    else:
        question += " y/n "
    while True:
        user_input = input(question).upper()
        if len(user_input) == 0 and default_return is not None:
            return default_return
        elif user_input[0] == "Y":
            return True
        elif user_input[0] == "N":
            return False


class Params:
    """
    Class that stores and formats parameters passed to the script
    """
    sys_args_dict = sys_args = None

    def __init__(self):
        Params.sys_args_dict = {}
        Params.sys_args = sys.argv[1:]

        for i in range(len(Params.sys_args)):
            if Params.sys_args[i].startswith('-'):
                Params.sys_args_dict[Params.sys_args[i]] = None
            elif i != 0 and Params.sys_args[i - 1].startswith('-'):
                Params.sys_args_dict[Params.sys_args[i - 1]] = Params.sys_args[i]
            else:
                Params.sys_args_dict[Params.sys_args[i]] = None

    @staticmethod
    def param_exists(param_name):
        """Finds a parameter by given name
        :param param_name name of the parameter
        :return True if found, False otherwise
        """
        return param_name in Params.sys_args_dict.keys()

    @staticmethod
    def get_param(param_name):
        """Finds a parameter by given name
        :param param_name name of the parameter
        :return assigned value or None if not found
        """
        if param_name in Params.sys_args_dict.keys():
            return Params.sys_args_dict[param_name]
        return None

    @staticmethod
    def get_file():
        """
        If last parameter is not assigned to any other parameter, expect it is a file
        :return file path or None
        """
        if len(Params.sys_args) != 0 and Params.sys_args[-1] not in Params.sys_args_dict.keys():
            return Params.sys_args[-1]
        return None


if __name__ == '__main__':
    Params()  # Init params
    main()
