import hashlib
import json
import os

import jsonschema

from .node_provider import get_default_config

MC2_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "mc2-schema.json")


def validate_config(config):
    """Required Dicts indicate that no extra fields can be introduced."""
    if not isinstance(config, dict):
        raise ValueError("Config {} is not a dictionary".format(config))

    with open(MC2_SCHEMA_PATH) as f:
        schema = json.load(f)
    try:
        jsonschema.validate(config, schema)
    except jsonschema.ValidationError as e:
        raise jsonschema.ValidationError(message=e.message) from None


def prepare_config(config):
    with_defaults = fillout_defaults(config)
    merge_setup_commands(with_defaults)
    return with_defaults


def fillout_defaults(config):
    defaults = get_default_config(config["provider"])
    defaults.update(config)
    defaults["auth"] = defaults.get("auth", {})
    return defaults


def merge_setup_commands(config):
    config["head_setup_commands"] = (
        config["setup_commands"] + config["head_setup_commands"]
    )
    config["worker_setup_commands"] = (
        config["setup_commands"] + config["worker_setup_commands"]
    )
    return config


def hash_launch_conf(node_conf, auth):
    hasher = hashlib.sha1()
    hasher.update(json.dumps([node_conf, auth], sort_keys=True).encode("utf-8"))
    return hasher.hexdigest()


# Cache the file hashes to avoid rescanning it each time. Also, this avoids
# inadvertently restarting workers if the file mount content is mutated on the
# head node.
_hash_cache = {}


def hash_runtime_conf(file_mounts, extra_objs):
    hasher = hashlib.sha1()

    def add_content_hashes(path):
        def add_hash_of_file(fpath):
            opaque_client_toolchain_path = os.path.dirname(__file__)
            fpath = os.path.join(opaque_client_toolchain_path, fpath)
            with open(fpath, "rb") as f:
                for chunk in iter(lambda: f.read(2 ** 20), b""):
                    hasher.update(chunk)

        path = os.path.expanduser(path)
        if os.path.isdir(path):
            dirs = []
            for dirpath, _, filenames in os.walk(path):
                dirs.append((dirpath, sorted(filenames)))
            for dirpath, filenames in sorted(dirs):
                hasher.update(dirpath.encode("utf-8"))
                for name in filenames:
                    hasher.update(name.encode("utf-8"))
                    fpath = os.path.join(dirpath, name)
                    add_hash_of_file(fpath)
        else:
            add_hash_of_file(path)

    conf_str = json.dumps(file_mounts, sort_keys=True).encode("utf-8") + json.dumps(
        extra_objs, sort_keys=True
    ).encode("utf-8")

    # Important: only hash the files once. Otherwise, we can end up restarting
    # workers if the files were changed and we re-hashed them.
    if conf_str not in _hash_cache:
        hasher.update(conf_str)
        for local_path in sorted(file_mounts.values()):
            add_content_hashes(local_path)
        _hash_cache[conf_str] = hasher.hexdigest()

    return _hash_cache[conf_str]
