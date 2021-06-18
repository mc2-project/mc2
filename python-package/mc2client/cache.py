"""
This module provides caching functionality to MC2 Client so that state can
be maintained across CLI calls. Currently, the following things are cached:
    * Whether the TMS has been attested
    * State information for each process spawned via `start()`. This state is
    used by `stop()` to terminate these processes.
"""
import json
import os


def cache_op(op):
    """
    A function decorater for cache operations.

    This decorater will check for the existence of a cache, create one if needed,
    and handle the serialization/deserialization of the cache to disk before and
    after function calls.

    parameters
    ----------
    f : function
        The function to be executed
    op : str
        "create" if adding an entry to the cache, "check" otherwise
    """

    def prelude_wrapper(f):
        def prelude(*args, **kwargs):
            global cache

            # Load the cache from disk if it exists
            cache_path = os.path.expanduser("~/.cache/mc2")
            if not os.path.exists(cache_path):
                if op == "check":
                    # If we're viewing or removing a cache entry and the cache
                    # doesn't exist, return without doing anything
                    return None
                elif op == "create":
                    # Otherwise, create the cache before executing `f`
                    try:
                        os.makedirs(os.path.expanduser("~/.cache"))
                    except FileExistsError:
                        pass
                    cache = dict()
            else:
                cache = json.load(open(cache_path))

            # Execute `f` which will have access to `cache`
            ret_val = f(*args, cache=cache, **kwargs)

            # Serialize `cache` to disk
            with open(cache_path, "w") as cache_file:
                json.dump(cache, cache_file)

            return ret_val

        return prelude

    return prelude_wrapper


@cache_op("create")
def add_cache_entry(key, value, cache=dict()):
    """
    Add `value` to the Opaque Client cache at index `key`. This will overwrite
    any existing values at `key`.

    parameters
    ----------
    key : str
        Key in the cache
    value: (valid JSON type)
        The value to store in the cache
    cache: dict
        The cache dictionary. This should only be set by the decorator function.
    """
    cache[key] = value


@cache_op("check")
def get_cache_entry(key, cache=dict()):
    """
    Return the value at index `key` in the Opaque Client cache or None if the
    index `key` doesn't exist.

    parameters
    ----------
    key : str
        Key in the cache
    cache: dict
        The cache dictionary. This should only be set by the decorator function.
    """
    return cache.get(key)


@cache_op("check")
def remove_cache_entry(key, cache=dict()):
    """
    Remove the value at index `key` from the Opaque Client cache and return it.
    Returns None if the index `key` doesn't exist.

    parameters
    ----------
    key : str
        Key in the cache
    cache: dict
        The cache dictionary. This should only be set by the decorator function.
    """
    return cache.pop(key, None)
