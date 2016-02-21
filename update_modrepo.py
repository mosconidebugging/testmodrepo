#!/usr/bin/env python3

import json
import zipfile
import glob
import traceback
import os
import logging
import copy

DEFAULT_MOD_JSON = {
    "author": "",
    "description": "",
    "name": "",
    "type": "mod",
    "url": "",
    "versions": {}
}

REQUIRED_FIELDS_MOD_JSON = {
    "author",
    "description",
    "name",
    "type",
    "url"
}

MOD_JSON_FILE = "mod.json"

DEFAULT_MC_VERSION = "1.7.10"

log_formatter = logging.Formatter("[%(levelname)-7.7s] %(message)s")

stdout_log_handler = logging.StreamHandler()
stdout_log_handler.setFormatter(log_formatter)

file_log_handler = logging.FileHandler("modrepo.log")
file_log_handler.setFormatter(log_formatter)

log = logging.getLogger("modrepo")
log.setLevel(logging.INFO)
log.addHandler(stdout_log_handler)
log.addHandler(file_log_handler)

def write_default_mod_json(mod_name):
    mod_json = copy.deepcopy(DEFAULT_MOD_JSON)
    mod_json["name"] = mod_name

    with open(MOD_JSON_FILE, "w") as fp:
        json.dump(mod_json, fp, sort_keys=True, indent=4)

def read_mod_json():
    with open(MOD_JSON_FILE, "r") as modFP:
        return json.load(modFP)

def write_mod_json(mod_json):
    with open(MOD_JSON_FILE, "w") as fp:
        json.dump(mod_json, fp, sort_keys=True, indent=4)

def check_mod_json(mod_json):
    for required_field in REQUIRED_FIELDS_MOD_JSON:
        if required_field not in mod_json.keys():
            log.warning("Missing required property \"{0}\"".format(required_field))
            mod_json[required_field] = DEFAULT_MOD_JSON[required_field]

def parse_info_file(mcmod, mod_filename):
    info = json.loads(mcmod.read().decode('utf-8'), strict=False)

    if type(info) == list:
        info = info[0]

    if "modListVersion" in info.keys() and "modList" in info.keys():
        info = info["modList"][0]

    mod_version = info["version"]

    if "mcversion" not in info.keys():
        log.warning("Mod \"{0}\" has no \"mcversion\", default to \"{1}\""
        .format(mod_filename, DEFAULT_MC_VERSION))
        mod_mcversion = DEFAULT_MC_VERSION
    else:
        mod_mcversion = info["mcversion"]

    mod_info = { mod_version: {} }
    mod_info[mod_version]["file"] = mod_filename
    mod_info[mod_version]["type"] = "universal"
    mod_info[mod_version]["minecraft"] = [mod_mcversion]

    return mod_info

def standard_mod(mod):
    info_files = [
        "mcmod.info",
        "cccmod.info",
        "nei.info",
        "neimod.info",
        "litemod.json"
    ]

    for info_file in info_files:
        try:
            with mod.open(info_file) as mcmod:
                return parse_info_file(mcmod, mod.filename)
        except Exception as err:
            pass

    return False

def process_mod_directory(mod_name):
    try:
        mod_json = read_mod_json()
    except Exception:
        log.error("Failed to open mod's information, writing defaults")
        write_default_mod_json(mod_name)
        mod_json = read_mod_json()

    check_mod_json(mod_json)

    mod_json["versions"] = {}

    for file in glob.glob("*.jar"):
        with zipfile.ZipFile(file) as mod:
            version = standard_mod(mod)
            if version:
                log.info("Parsed correctly \"{0}\"".format(mod.filename))
                mod_json["versions"].update(version)
                write_mod_json(mod_json)
            else:
                log.error("Failed to parse \"{0}\"".format(mod.filename))

def scan_directories():
    base_directory = os.getcwd()
    log.info("Starting from base directory \"{0}\"".format(base_directory))

    directories = filter(lambda x: os.path.isdir(x), os.listdir(base_directory))
    directories = filter(lambda x: x != ".git", directories)
    directories = sorted(directories)

    for directory in directories:
        log.info("Processing mod \"{0}\"".format(directory))
        os.chdir(directory)
        process_mod_directory(directory)
        os.chdir(base_directory)

scan_directories()

