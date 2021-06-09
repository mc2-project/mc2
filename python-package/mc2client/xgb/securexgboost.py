import ctypes
import os
import re
import sys
from collections.abc import Mapping

import grpc
import numpy as np

from ..core import (
    _CONF,
    _LIB,
    _check_call,
    _check_remote_call,
    c_str,
    ctypes2buffer,
    ctypes2numpy,
    from_cstr_to_pystr,
    from_pystr_to_cstr,
    pointer_to_proto,
    proto_to_pointer,
    sign_data,
)
from ..rpc import (  # pylint: disable=no-name-in-module
    remote_pb2,
    remote_pb2_grpc,
)

CIPHER_IV_SIZE = 12
CIPHER_TAG_SIZE = 16
CIPHER_NONCE_SIZE = 16
c_bst_ulong = ctypes.c_uint64

# from XGBoost
STRING_TYPES = (str,)

# pandas
try:
    from pandas import DataFrame, MultiIndex

    PANDAS_INSTALLED = True
except ImportError:

    # pylint: disable=too-few-public-methods
    class MultiIndex(object):
        """ dummy for pandas.MultiIndex """

    # pylint: disable=too-few-public-methods
    class DataFrame(object):
        """ dummy for pandas.DataFrame """

    PANDAS_INSTALLED = False


class DMatrix(object):
    """Data Matrix used in Secure XGBoost.

    DMatrix is a internal data structure that used by XGBoost
    which is optimized for both memory efficiency and training speed.

    You can load a DMatrix from one ore more encrypted files at the enclave server, where
    each file is encrypted with a particular user's symmetric key.
    Each DMatrix in Secure XGBoost is thus associated with one or more data owners.
    """

    _feature_names = None  # for previous version's pickle
    _feature_types = None

    # TODO(rishabh): Enable disabled arguments: `label`, `weight`
    def __init__(
        self,
        data_dict,
        encrypted=True,
        silent=False,
        feature_names=None,
        feature_types=None,
    ):
        """
        Parameters
        ----------
        data_dict : dict, {str: str}
            The keys are usernames.
            The values are absolute paths to the training data of the corresponding user in the cloud.
        encrypted : bool, optional
            Whether data is encrypted
        silent : bool, optional
            Whether to print messages during construction
        feature_names : list, optional
            Set names for features.
        feature_types : list, optional
            Set types for features.
        """

        usernames, data = [], []

        for user, path in data_dict.items():
            usernames.append(user)
            data.append(path)
        # Sort by username
        usernames, data = (
            list(x)
            for x in zip(*sorted(zip(usernames, data), key=lambda pair: pair[0]))
        )

        if isinstance(data, list):

            # Normalize file paths (otherwise signatures might differ)
            data = [os.path.normpath(path) for path in data]

            handle = ctypes.c_char_p()
            if encrypted:
                args = "XGDMatrixCreateFromEncryptedFile"
                for username, filename in zip(usernames, data):
                    args = args + " username {} filename {}".format(username, filename)
                args = args + " silent {}".format(int(silent))
                sig, sig_len = create_client_signature(args)

                out_sig = ctypes.POINTER(ctypes.c_uint8)()
                out_sig_length = c_bst_ulong()

                channel_addr = _CONF["remote_addr"]
                with grpc.insecure_channel(channel_addr) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    dmatrix_attrs = remote_pb2.DMatrixAttrs(
                        filenames=data, usernames=usernames, silent=silent
                    )
                    seq_num = get_seq_num_proto()
                    response = _check_remote_call(
                        stub.rpc_XGDMatrixCreateFromEncryptedFile(
                            remote_pb2.DMatrixAttrsRequest(
                                params=dmatrix_attrs,
                                seq_num=seq_num,
                                username=_CONF["current_user"],
                                signature=sig,
                                sig_len=sig_len,
                            )
                        )
                    )
                    handle = c_str(response.name)
                    out_sig = proto_to_pointer(response.signature)
                    out_sig_length = c_bst_ulong(response.sig_len)

                args = "handle {}".format(handle.value.decode("utf-8"))
                verify_enclave_signature(args, len(args), out_sig, out_sig_length)

            else:
                raise NotImplementedError(
                    "Loading from unencrypted files not supported."
                )
                # FIXME implement RPC for this
                # FIXME handle multiparty case
                # _check_call(_LIB.XGDMatrixCreateFromFile(c_str(data),
                #     ctypes.c_int(silent),
                #     ctypes.byref(handle)))
            self.handle = handle
        # elif isinstance(data, scipy.sparse.csr_matrix):
        #     self._init_from_csr(data)
        # elif isinstance(data, scipy.sparse.csc_matrix):
        #     self._init_from_csc(data)
        # elif isinstance(data, np.ndarray):
        #     self._init_from_npy2d(data, missing, nthread)
        # elif isinstance(data, DataTable):
        #     self._init_from_dt(data, nthread)
        # else:
        #     try:
        #         csr = scipy.sparse.csr_matrix(data)
        #         self._init_from_csr(csr)
        #     except:
        #         raise TypeError('can not initialize DMatrix from'
        #                         ' {}'.format(type(data).__name__))

        # TODO(rishabh): Enable this
        # if label is not None:
        #     if isinstance(label, np.ndarray):
        #         self.set_label_npy2d(label)
        #     else:
        #         self.set_label(label)
        # if weight is not None:
        #     if isinstance(weight, np.ndarray):
        #         self.set_weight_npy2d(weight)
        #     else:
        #         self.set_weight(weight)

        self.feature_names = feature_names
        self.feature_types = feature_types

    def __del__(self):
        if hasattr(self, "handle") and self.handle is not None:
            # FIXME free matrix after use using RPC
            # _check_call(_LIB.XGDMatrixFree(self.handle))
            self.handle = None

    def num_row(self):
        """Get the number of rows in the DMatrix.

        Returns
        -------
        number of rows : int
        """
        channel_addr = _CONF["remote_addr"]
        args = "XGDMatrixNumRow " + self.handle.value.decode("utf-8")
        sig, sig_len = create_client_signature(args)

        ret = c_bst_ulong()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            name_proto = remote_pb2.NameRequestParams(name=self.handle.value)
            seq_num = get_seq_num_proto()
            response = _check_remote_call(
                stub.rpc_XGDMatrixNumRow(
                    remote_pb2.NumRowRequest(
                        params=name_proto,
                        seq_num=seq_num,
                        username=_CONF["current_user"],
                        signature=sig,
                        sig_len=sig_len,
                    )
                )
            )
            out_sig = proto_to_pointer(response.signature)
            out_sig_length = c_bst_ulong(response.sig_len)
            ret = response.value

        args = "{}".format(ret)
        verify_enclave_signature(args, len(args), out_sig, out_sig_length)

        return ret

    def num_col(self):
        """Get the number of columns (features) in the DMatrix.

        Returns
        -------
        number of columns : int
        """
        args = "XGDMatrixNumCol " + self.handle.value.decode("utf-8")
        sig, sig_len = create_client_signature(args)

        ret = c_bst_ulong()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        channel_addr = _CONF["remote_addr"]

        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            name_proto = remote_pb2.NameRequestParams(name=self.handle.value)
            seq_num = get_seq_num_proto()
            response = _check_remote_call(
                stub.rpc_XGDMatrixNumCol(
                    remote_pb2.NumColRequest(
                        params=name_proto,
                        seq_num=seq_num,
                        username=_CONF["current_user"],
                        signature=sig,
                        sig_len=sig_len,
                    )
                )
            )
            out_sig = proto_to_pointer(response.signature)
            out_sig_length = c_bst_ulong(response.sig_len)
            ret = response.value

        args = "{}".format(ret)
        verify_enclave_signature(args, len(args), out_sig, out_sig_length)
        return ret

    @property
    def feature_names(self):
        """Get feature names (column labels).

        Returns
        -------
        feature_names : list or None
        """
        if self._feature_names is None:
            self._feature_names = ["f{0}".format(i) for i in range(self.num_col())]
        return self._feature_names

    @property
    def feature_types(self):
        """Get feature types (column types).

        Returns
        -------
        feature_types : list or None
        """
        return self._feature_types

    @feature_names.setter
    def feature_names(self, feature_names):
        """Set feature names (column labels).

        Parameters
        ----------
        feature_names : list or None
            Labels for features. None will reset existing feature names
        """
        if feature_names is not None:
            # validate feature name
            try:
                if not isinstance(feature_names, str):
                    feature_names = [n for n in iter(feature_names)]
                else:
                    feature_names = [feature_names]
            except TypeError:
                feature_names = [feature_names]

            if len(feature_names) != len(set(feature_names)):
                raise ValueError("feature_names must be unique")
            if len(feature_names) != self.num_col():
                msg = "feature_names must have the same length as data"
                raise ValueError(msg)
            # prohibit to use symbols may affect to parse. e.g. []<
            if not all(
                isinstance(f, STRING_TYPES)
                and not any(x in f for x in set(("[", "]", "<")))
                for f in feature_names
            ):
                raise ValueError("feature_names may not contain [, ] or <")
        else:
            # reset feature_types also
            self.feature_types = None
        self._feature_names = feature_names

    @feature_types.setter
    def feature_types(self, feature_types):
        """Set feature types (column types).

        This is for displaying the results and unrelated
        to the learning process.

        Parameters
        ----------
        feature_types : list or None
            Labels for features. None will reset existing feature names
        """
        if feature_types is not None:
            if self._feature_names is None:
                msg = "Unable to set feature types before setting names"
                raise ValueError(msg)

            if isinstance(feature_types, STRING_TYPES):
                # single string will be applied to all columns
                feature_types = [feature_types] * self.num_col()

            try:
                if not isinstance(feature_types, str):
                    feature_types = [n for n in iter(feature_types)]
                else:
                    feature_types = [feature_types]
            except TypeError:
                feature_types = [feature_types]

            if len(feature_types) != self.num_col():
                msg = "feature_types must have the same length as data"
                raise ValueError(msg)

            valid = ("int", "float", "i", "q")
            if not all(
                isinstance(f, STRING_TYPES) and f in valid for f in feature_types
            ):
                raise ValueError("All feature_names must be {int, float, i, q}")
        self._feature_types = feature_types


def verify_enclave_signature(data, size, sig, sig_len, increment_nonce=True):
    """
    Verify the signature returned by the enclave with nonce
    """
    arr = (ctypes.c_char * (size + CIPHER_NONCE_SIZE))()
    add_to_sig_data(arr, data=data, data_size=size)
    add_nonce_to_sig_data(arr, pos=size)
    size = ctypes.c_size_t(len(arr))

    pem_key = _CONF["enclave_pk"]
    pem_key_len = _CONF["enclave_pk_size"]
    # Verify signature
    _check_call(_LIB.verify_signature(pem_key, pem_key_len, arr, size, sig, sig_len))

    if increment_nonce:
        _CONF["nonce_ctr"] += 1


def create_client_signature(args):
    """
    Sign the data for the enclave with nonce
    """
    arr = (ctypes.c_char * (len(args) + CIPHER_NONCE_SIZE))()
    add_to_sig_data(arr, data=args)
    add_nonce_to_sig_data(arr, pos=len(args))
    sig, sig_len = sign_data(_CONF["private_key"], arr, len(arr))
    return sig, sig_len


def add_to_sig_data(arr, pos=0, data=None, data_size=0):
    if isinstance(data, str):
        ctypes.memmove(ctypes.byref(arr, pos), c_str(data), len(data))
    else:
        ctypes.memmove(ctypes.byref(arr, pos), data, data_size)
    return arr


def add_nonce_to_sig_data(arr, pos=0):
    ctypes.memmove(ctypes.byref(arr, pos), _CONF["nonce"], 12)
    ctypes.memmove(
        ctypes.byref(arr, pos + 12), _CONF["nonce_ctr"].to_bytes(4, "big"), 4
    )
    return arr


def get_seq_num_proto():
    return remote_pb2.SequenceNumber(
        nonce=pointer_to_proto(_CONF["nonce"], _CONF["nonce_size"].value),
        nonce_size=_CONF["nonce_size"].value,
        nonce_ctr=_CONF["nonce_ctr"],
    )


class Booster(object):
    # pylint: disable=too-many-public-methods
    """A Booster of Secure XGBoost.

    Booster is the model of Secure XGBoost, that contains low level routines for
    training, prediction and evaluation.
    """

    feature_names = None

    def __init__(self, params=None, cache=(), model_file=None):
        # pylint: disable=invalid-name
        """
        Parameters
        ----------
        params : dict
            Parameters for boosters.
        cache : list
            List of cache items.
        model_file : str
            Path to the model file.
        """
        for d in cache:
            if not isinstance(d, DMatrix):
                raise TypeError("invalid cache item: {}".format(type(d).__name__))
            self._validate_features(d)

        args = "XGBoosterCreate"
        sig, sig_len = create_client_signature(args)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        channel_addr = _CONF["remote_addr"]
        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            cache_handles = [d.handle.value for d in cache]
            booster_attrs = remote_pb2.BoosterAttrs(
                cache=cache_handles, length=len(cache)
            )
            seq_num = get_seq_num_proto()
            response = _check_remote_call(
                stub.rpc_XGBoosterCreate(
                    remote_pb2.BoosterAttrsRequest(
                        params=booster_attrs,
                        seq_num=seq_num,
                        username=_CONF["current_user"],
                        signature=sig,
                        sig_len=sig_len,
                    )
                )
            )
        self.handle = c_str(response.name)
        out_sig = proto_to_pointer(response.signature)
        out_sig_length = c_bst_ulong(response.sig_len)

        args = "handle {}".format(self.handle.value.decode("utf-8"))
        verify_enclave_signature(args, len(args), out_sig, out_sig_length)

        self.set_param({"seed": 0})
        self.set_param(params or {})

        if (params is not None) and ("booster" in params):
            self.booster = params["booster"]
        else:
            self.booster = "gbtree"

        if model_file is not None:
            self.load_model(model_file)

    def __del__(self):
        if hasattr(self, "handle") and self.handle is not None:
            # FIXME free booster after use using RPC
            # _check_call(_LIB.XGBoosterFree(self.handle))
            self.handle = None

    def __copy__(self):
        return self.__deepcopy__(None)

    def __deepcopy__(self, _):
        return Booster(model_file=self.save_raw())

    def copy(self):
        """Copy the booster object.

        Returns
        -------
        booster: `Booster`
            a copied booster model
        """
        return self.__copy__()

    def set_param(self, params, value=None):
        """Set parameters into the Booster.

        Parameters
        ----------
        params: dict/list/str
           list of key,value pairs, dict of key to value or simply str key
        value: optional
           value of the specified parameter, when params is str key
        """
        if isinstance(params, Mapping):
            params = params.items()
        elif isinstance(params, STRING_TYPES) and value is not None:
            params = [(params, value)]

        if "current_user" in _CONF:
            user = _CONF["current_user"]
        else:
            raise ValueError("Please add your username to the YAML config")

        for key, val in params:
            args = (
                "XGBoosterSetParam "
                + self.handle.value.decode("utf-8")
                + " "
                + key
                + ","
                + str(val)
            )
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                booster_param = remote_pb2.BoosterParam(
                    booster_handle=self.handle.value, key=key, value=str(val)
                )
                seq_num = get_seq_num_proto()
                response = _check_remote_call(
                    stub.rpc_XGBoosterSetParam(
                        remote_pb2.BoosterParamRequest(
                            params=booster_param,
                            seq_num=seq_num,
                            username=user,
                            signature=sig,
                            sig_len=sig_len,
                        )
                    )
                )
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)

            verify_enclave_signature("", 0, out_sig, out_sig_length)

    def update(self, dtrain, iteration, fobj=None):
        """Update for one iteration, with objective function calculated
        internally.  This function should not be called directly by users.

        Parameters
        ----------
        dtrain : DMatrix
            Training data.
        iteration : int
            Current iteration number.
        fobj : function
            Customized objective function.

        """
        if not isinstance(dtrain, DMatrix):
            raise TypeError("invalid training matrix: {}".format(type(dtrain).__name__))
        self._validate_features(dtrain)

        if fobj is None:
            args = "XGBoosterUpdateOneIter booster_handle {} iteration {} train_data_handle {}".format(
                self.handle.value.decode("utf-8"),
                int(iteration),
                dtrain.handle.value.decode("utf-8"),
            )
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                booster_update_params = remote_pb2.BoosterUpdateParams(
                    booster_handle=self.handle.value,
                    dtrain_handle=dtrain.handle.value,
                    iteration=iteration,
                )
                seq_num = get_seq_num_proto()
                response = _check_remote_call(
                    stub.rpc_XGBoosterUpdateOneIter(
                        remote_pb2.BoosterUpdateParamsRequest(
                            params=booster_update_params,
                            seq_num=seq_num,
                            username=_CONF["current_user"],
                            signature=sig,
                            sig_len=sig_len,
                        )
                    )
                )
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)
            verify_enclave_signature("", 0, out_sig, out_sig_length)
        else:
            raise NotImplementedError("Custom objective functions not supported")
            # TODO(rishabh): We do not support custom objectives currently
            # pred = self.predict(dtrain)
            # grad, hess = fobj(pred, dtrain)
            # self.boost(dtrain, grad, hess)

    def predict(
        self,
        data,
        output_margin=False,
        ntree_limit=0,
        pred_leaf=False,
        pred_contribs=False,
        approx_contribs=False,
        pred_interactions=False,
        validate_features=True,
        training=False,
        decrypt=True,
    ):
        """
        Predict with data.

        .. note:: This function is not thread safe.

          For each booster object, predict can only be called from one thread.
          If you want to run prediction using multiple thread, call ``bst.copy()`` to make copies
          of model object and then call ``predict()``.

        .. note:: Using ``predict()`` with DART booster

          If the booster object is DART type, ``predict()`` will perform dropouts, i.e. only
          some of the trees will be evaluated. This will produce incorrect results if ``data`` is
          not the training data. To obtain correct results on test sets, set ``ntree_limit`` to
          a nonzero value, e.g.

          .. code-block:: python

            preds = bst.predict(dtest, ntree_limit=num_round)

        Parameters
        ----------
        data : DMatrix
            The dmatrix storing the input.

        output_margin : bool
            Whether to output the raw untransformed margin value.

        ntree_limit : int
            Limit number of trees in the prediction; defaults to 0 (use all trees).

        pred_leaf : bool
            When this option is on, the output will be a matrix of (nsample, ntrees)
            with each record indicating the predicted leaf index of each sample in each tree.
            Note that the leaf index of a tree is unique per tree, so you may find leaf 1
            in both tree 1 and tree 0.

        pred_contribs : bool
            When this is True the output will be a matrix of size (nsample, nfeats + 1)
            with each record indicating the feature contributions (SHAP values) for that
            prediction. The sum of all feature contributions is equal to the raw untransformed
            margin value of the prediction. Note the final column is the bias term.

        approx_contribs : bool
            Approximate the contributions of each feature

        pred_interactions : bool
            When this is True the output will be a matrix of size (nsample, nfeats + 1, nfeats + 1)
            indicating the SHAP interaction values for each pair of features. The sum of each
            row (or column) of the interaction values equals the corresponding SHAP value (from
            pred_contribs), and the sum of the entire matrix equals the raw untransformed margin
            value of the prediction. Note the last row and column correspond to the bias term.

        training : bool
            Whether the prediction value is used for training.  This can effect
            `dart` booster, which performs dropouts during training iterations.

        .. note:: Using ``predict()`` with DART booster

          If the booster object is DART type, ``predict()`` will not perform
          dropouts, i.e. all the trees will be evaluated.  If you want to
          obtain result with dropouts, provide `training=True`.

        validate_features : bool
            When this is True, validate that the Booster's and data's feature_names are identical.
            Otherwise, it is assumed that the feature_names are the same.

        decrypt: bool
            When this is True, the predictions received from the enclave are decrypted using the user's symmetric key

        Returns
        -------
        prediction : list
            List of predictions. Each element in the list is a set of predictions from a different node in the cloud.
        num_preds: list
            Number of predictions in each element in `prediction`
        """
        # check the global variable for current_user
        if "current_user" in _CONF:
            username = _CONF["current_user"]
        else:
            raise ValueError("Please set your username with the init_user() function")
        option_mask = 0x00
        if output_margin:
            option_mask |= 0x01
        if pred_leaf:
            option_mask |= 0x02
        if pred_contribs:
            option_mask |= 0x04
        if approx_contribs:
            option_mask |= 0x08
        if pred_interactions:
            option_mask |= 0x10

        if validate_features:
            self._validate_features(data)

        preds = ctypes.POINTER(ctypes.c_uint8)()

        args = "XGBoosterPredict booster_handle {} data_handle {} option_mask {} ntree_limit {}".format(
            self.handle.value.decode("utf-8"),
            data.handle.value.decode("utf-8"),
            int(option_mask),
            int(ntree_limit),
        )
        sig, sig_len = create_client_signature(args)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        channel_addr = _CONF["remote_addr"]
        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            predict_params = remote_pb2.PredictParams(
                booster_handle=self.handle.value,
                dmatrix_handle=data.handle.value,
                option_mask=option_mask,
                ntree_limit=ntree_limit,
                training=training,
            )
            seq_num = get_seq_num_proto()
            response = _check_remote_call(
                stub.rpc_XGBoosterPredict(
                    remote_pb2.PredictParamsRequest(
                        params=predict_params,
                        seq_num=seq_num,
                        username=username,
                        signature=sig,
                        sig_len=sig_len,
                    )
                )
            )
            # List of list of predictions
            enc_preds_serialized_list = response.predictions
            length_list = list(response.num_preds)

            # List of signatures
            out_sigs_serialized_list = response.signatures
            out_sig_length_list = list(response.sig_lens)

            preds_list = [
                proto_to_pointer(enc_preds_serialized)
                for enc_preds_serialized in enc_preds_serialized_list
            ]
            out_sigs = [
                proto_to_pointer(out_sig_serialized)
                for out_sig_serialized in out_sigs_serialized_list
            ]
            out_sig_lengths_ulong = [
                c_bst_ulong(length) for length in out_sig_length_list
            ]

            # Verify signatures
            for i in range(len(preds_list)):
                preds = preds_list[i]
                enc_preds_length = length_list[i]
                size = (
                    enc_preds_length * ctypes.sizeof(ctypes.c_float)
                    + CIPHER_IV_SIZE
                    + CIPHER_TAG_SIZE
                )

                out_sig = out_sigs[i]
                out_sig_length = out_sig_lengths_ulong[i]

                if i != len(preds_list) - 1:
                    verify_enclave_signature(
                        preds, size, out_sig, out_sig_length, increment_nonce=False
                    )
                else:
                    verify_enclave_signature(
                        preds, size, out_sig, out_sig_length, increment_nonce=True
                    )

            if decrypt:
                preds = self.decrypt_predictions(preds_list, length_list)
                return preds, sum(length_list)

            return preds_list, length_list

    # TODO(rishabh): change encrypted_preds to Python type from ctype
    def decrypt_predictions(self, encrypted_preds, num_preds):
        """
        Decrypt encrypted predictions

        Parameters
        ----------
        key : byte array
            key used to encrypt client files
        encrypted_preds : c_char_p
            encrypted predictions
        num_preds : int
            number of predictions

        Returns
        -------
        preds : numpy array
            plaintext predictions
        """
        try:
            symm_key_path = _CONF["symm_key"]
        except KeyError:
            raise KeyError("Client symmetric key not found")

        with open(symm_key_path, "rb") as symm_keyfile:
            user_symm_key = symm_keyfile.read()

        # Cast arguments to proper ctypes
        c_char_p_key = ctypes.c_char_p(user_symm_key)

        preds_list = []
        for i in range(len(encrypted_preds)):
            size_t_num_preds = ctypes.c_size_t(num_preds[i])
            preds = ctypes.POINTER(ctypes.c_float)()

            _check_call(
                _LIB.decrypt_predictions(
                    c_char_p_key,
                    encrypted_preds[i],
                    size_t_num_preds,
                    ctypes.byref(preds),
                )
            )

            # Convert c pointer to numpy array
            preds = ctypes2numpy(preds, num_preds[i], np.float32)
            preds_list.append(preds)

        concatenated_preds = np.concatenate(preds_list)
        return concatenated_preds

    def save_model(self, fname):
        """
        Save the model to an encrypted file at the server.
        The file is encrypted with the user's symmetric key.

        The model is saved in an XGBoost internal binary format which is
        universal among the various XGBoost interfaces. Auxiliary attributes of
        the Python Booster object (such as feature_names) will not be saved.
        To preserve all attributes, pickle the Booster object.

        Parameters
        ----------
        fname : str
            Absolute path to save the model to
        """
        # check the global variable for current_user
        if "current_user" in _CONF:
            username = _CONF["current_user"]
        else:
            raise ValueError("Please set your username in the config YAML")
        if isinstance(fname, STRING_TYPES):  # assume file name

            # Normalize file paths (otherwise signatures might differ)
            fname = os.path.normpath(fname)

            args = "XGBoosterSaveModel handle {} filename {}".format(
                self.handle.value.decode("utf-8"), fname
            )
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]

            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                save_model_params = remote_pb2.SaveModelParams(
                    booster_handle=self.handle.value, filename=fname
                )
                seq_num = get_seq_num_proto()
                response = _check_remote_call(
                    stub.rpc_XGBoosterSaveModel(
                        remote_pb2.SaveModelParamsRequest(
                            params=save_model_params,
                            seq_num=seq_num,
                            username=username,
                            signature=sig,
                            sig_len=sig_len,
                        )
                    )
                )
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)

            verify_enclave_signature("", 0, out_sig, out_sig_length)
        else:
            raise TypeError("fname must be a string")

    # FIXME Should we decrypt the raw model?
    def save_raw(self):
        """
        Save the model to a in memory buffer representation.
        The model is encrypted with the user's symmetric key.

        Returns
        -------
        a in memory buffer representation of the model
        """
        # check the global variable for current_user
        if "current_user" in _CONF:
            username = _CONF["current_user"]
        else:
            raise ValueError("Please set your username in the config YAML")

        length = c_bst_ulong()
        cptr = ctypes.POINTER(ctypes.c_char)()

        args = "XGBoosterGetModelRaw handle {}".format(
            self.handle.value.decode("utf-8")
        )
        sig, sig_len = create_client_signature(args)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        channel_addr = _CONF["remote_addr"]
        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            model_raw_params = remote_pb2.ModelRawParams(
                booster_handle=self.handle.value
            )
            seq_num = get_seq_num_proto()
            response = _check_remote_call(
                stub.rpc_XGBoosterGetModelRaw(
                    params=model_raw_params,
                    seq_num=seq_num,
                    username=username,
                    signature=sig,
                    sig_len=sig_len,
                )
            )
            cptr = from_pystr_to_cstr(list(response.sarr))
            length = c_bst_ulong(response.length)
            out_sig = proto_to_pointer(response.signature)
            out_sig_length = c_bst_ulong(response.sig_len)

        verify_enclave_signature(cptr, length.value, out_sig, out_sig_length)
        return ctypes2buffer(cptr, length.value)

    def load_model(self, fname):
        """
        Load the model from a file.

        The model is loaded from an XGBoost internal binary format which is
        universal among the various XGBoost interfaces. Auxiliary attributes of
        the Python Booster object (such as feature_names) will not be loaded.
        To preserve all attributes, pickle the Booster object.

        Parameters
        ----------
        fname : str or a memory buffer
            Input file name or memory buffer(see also save_raw)
        """
        # check the global variable for current_user
        if "current_user" in _CONF:
            username = _CONF["current_user"]
        else:
            raise ValueError("Please set your username with the init_user() function")

        if isinstance(fname, STRING_TYPES):
            # Normalize file paths (otherwise signatures might differ)
            fname = os.path.normpath(fname)

            # assume file name, cannot use os.path.exist to check, file can be from URL.
            args = "XGBoosterLoadModel handle {} filename {}".format(
                self.handle.value.decode("utf-8"), fname
            )
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                load_model_params = remote_pb2.LoadModelParams(
                    booster_handle=self.handle.value, filename=fname
                )

                seq_num = get_seq_num_proto()

                response = _check_remote_call(
                    stub.rpc_XGBoosterLoadModel(
                        remote_pb2.LoadModelParamsRequest(
                            params=load_model_params,
                            seq_num=seq_num,
                            username=username,
                            signature=sig,
                            sig_len=sig_len,
                        )
                    )
                )
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)

            verify_enclave_signature("", 0, out_sig, out_sig_length)
        else:
            # FIXME: Remote execution for non-file type
            raise "NotImplementedError"
            # buf = fname
            # length = c_bst_ulong(len(buf))
            # ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            # _check_call(_LIB.XGBoosterLoadModelFromBuffer(self.handle, ptr, length, c_str(username)))

    def dump_model(self, fout, fmap="", with_stats=False, dump_format="text"):
        """
        Dump model into a text or JSON file.

        Parameters
        ----------
        fout : str
            Output file name.
        fmap : str, optional
            Name of the file containing feature map names.
        with_stats : bool, optional
            Controls whether the split statistics are output.
        dump_format : str, optional
            Format of model dump file. Can be 'text' or 'json'.
        """
        if isinstance(fout, STRING_TYPES):
            fout = open(fout, "w")
            need_close = True
        else:
            need_close = False
        ret = self.get_dump(fmap, with_stats, dump_format)
        if dump_format == "json":
            fout.write("[\n")
            for i, _ in enumerate(ret):
                fout.write(ret[i])
                if i < len(ret) - 1:
                    fout.write(",\n")
            fout.write("\n]")
        else:
            for i, _ in enumerate(ret):
                fout.write("booster[{}]:\n".format(i))
                fout.write(ret[i])
        if need_close:
            fout.close()

    def get_dump(self, fmap="", with_stats=False, dump_format="text", decrypt=True):
        """
        Returns the (encrypted) model dump as a list of strings.
        The model is encrypted with the user's symmetric key.
        If `decrypt` is True, then the dump is decrypted by the client.

        Parameters
        ----------
        fmap : str, optional
            Name of the file containing feature map names.
        with_stats : bool, optional
            Controls whether the split statistics are output.
        dump_format : str, optional
            Format of model dump. Can be 'text' or 'json'.
        decrypt: bool
            When this is True, the model dump received from the enclave is decrypted using the user's symmetric key

        Returns
        -------
        res : str
            A string representation of the model dump
        """
        length = c_bst_ulong()
        sarr = ctypes.POINTER(ctypes.c_char_p)()

        if self.feature_names is not None and fmap == "":
            flen = len(self.feature_names)

            fname = self.feature_names
            if self.feature_types is None:
                # use quantitative as default
                # {'q': quantitative, 'i': indicator}
                ftype = ["q"] * flen
            else:
                ftype = self.feature_types

            args = "XGBoosterDumpModelExWithFeatures booster_handle {} flen {} with_stats {} dump_format {}".format(
                self.handle.value.decode("utf-8"), flen, int(with_stats), dump_format
            )
            for i in range(flen):
                args = args + " fname {} ftype {}".format(fname[i], ftype[i])
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                dump_model_with_features_params = (
                    remote_pb2.DumpModelWithFeaturesParams(
                        booster_handle=self.handle.value,
                        flen=flen,
                        fname=fname,
                        ftype=ftype,
                        with_stats=with_stats,
                        dump_format=dump_format,
                    )
                )
                seq_num = get_seq_num_proto()
                response = _check_remote_call(
                    stub.rpc_XGBoosterDumpModelExWithFeatures(
                        remote_pb2.DumpModelWithFeaturesParamsRequest(
                            params=dump_model_with_features_params,
                            seq_num=seq_num,
                            username=_CONF["current_user"],
                            signature=sig,
                            sig_len=sig_len,
                        )
                    )
                )
                sarr = from_pystr_to_cstr(list(response.sarr))
                length = c_bst_ulong(response.length)
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)

        else:
            if fmap != "" and not os.path.exists(fmap):
                raise ValueError("No such file: {0}".format(fmap))

            args = "XGBoosterDumpModelEx booster_handle {} fmap {} with_stats {} dump_format {}".format(
                self.handle.value.decode("utf-8"), fmap, int(with_stats), dump_format
            )
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                dump_model_params = remote_pb2.DumpModelParams(
                    booster_handle=self.handle.value,
                    fmap=fmap,
                    with_stats=with_stats,
                    dump_format=dump_format,
                )
                seq_num = get_seq_num_proto()
                response = _check_remote_call(
                    stub.rpc_XGBoosterDumpModelEx(
                        remote_pb2.DumpModelParamsRequest(
                            params=dump_model_params,
                            seq_num=seq_num,
                            username=_CONF["current_user"],
                            signature=sig,
                            sig_len=sig_len,
                        )
                    )
                )
                sarr = from_pystr_to_cstr(list(response.sarr))
                length = c_bst_ulong(response.length)
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)

        py_sarr = from_cstr_to_pystr(sarr, length)
        data = "".join(py_sarr)
        verify_enclave_signature(data, len(data), out_sig, out_sig_length)

        if decrypt:
            self.decrypt_dump(sarr, length)
        res = from_cstr_to_pystr(sarr, length)
        return res

    def decrypt_dump(self, sarr, length):
        """
        Decrypt the models obtained from get_dump()

        Parameters
        ----------
        sarr: str
            Encrypted string representation of the model obtained from get_dump()
        length : int
           length of sarr
        """
        try:
            enclave_sym_key = _CONF["enclave_sym_key"]
        except KeyError:
            raise KeyError("Enclave symmetric key not found.")

        _check_call(_LIB.decrypt_dump(enclave_sym_key, sarr, length))

    def get_fscore(self, fmap=""):
        """Get feature importance of each feature.

        .. note:: Feature importance is defined only for tree boosters

        Feature importance is only defined when the decision tree model is chosen as base
        learner (`booster=gbtree`). It is not defined for other base learner types, such
        as linear learners (`booster=gblinear`).

        .. note:: Zero-importance features will not be included

        Keep in mind that this function does not include zero-importance feature, i.e.
        those features that have not been used in any split conditions.

        Parameters
        ----------
        fmap: str (optional)
            The name of feature map file
        """

        return self.get_score(fmap, importance_type="weight")

    def get_score(self, fmap="", importance_type="weight"):
        """Get feature importance of each feature.
        Importance type can be defined as:

        * 'weight': the number of times a feature is used to split the data across all trees.
        * 'gain': the average gain across all splits the feature is used in.
        * 'cover': the average coverage across all splits the feature is used in.
        * 'total_gain': the total gain across all splits the feature is used in.
        * 'total_cover': the total coverage across all splits the feature is used in.

        .. note:: Feature importance is defined only for tree boosters

            Feature importance is only defined when the decision tree model is chosen as base
            learner (`booster=gbtree`). It is not defined for other base learner types, such
            as linear learners (`booster=gblinear`).

        Parameters
        ----------
        fmap: str (optional)
           The name of feature map file.
        importance_type: str, default 'weight'
            One of the importance types defined above.
        """
        if getattr(self, "booster", None) is not None and self.booster not in {
            "gbtree",
            "dart",
        }:
            raise ValueError(
                "Feature importance is not defined for Booster type {}".format(
                    self.booster
                )
            )

        allowed_importance_types = [
            "weight",
            "gain",
            "cover",
            "total_gain",
            "total_cover",
        ]
        if getattr(self, "booster", None) is not None and self.booster not in {
            "gbtree",
            "dart",
        }:
            raise ValueError(
                "Feature importance is not defined for Booster type {}".format(
                    self.booster
                )
            )

        allowed_importance_types = [
            "weight",
            "gain",
            "cover",
            "total_gain",
            "total_cover",
        ]

        if importance_type not in allowed_importance_types:
            msg = "importance_type mismatch, got '{}', expected one of " + repr(
                allowed_importance_types
            )
            raise ValueError(msg.format(importance_type))

        # if it's weight, then omap stores the number of missing values
        if importance_type == "weight":
            # do a simpler tree dump to save time
            trees = self.get_dump(fmap, with_stats=False)

            fmap = {}
            for tree in trees:
                for line in tree.split("\n"):
                    # look for the opening square bracket
                    arr = line.split("[")
                    # if no opening bracket (leaf node), ignore this line
                    if len(arr) == 1:
                        continue

                    # extract feature name from string between []
                    fid = arr[1].split("]")[0].split("<")[0]

                    if fid not in fmap:
                        # if the feature hasn't been seen yet
                        fmap[fid] = 1
                    else:
                        fmap[fid] += 1

            return fmap

        average_over_splits = True
        if importance_type == "total_gain":
            importance_type = "gain"
            average_over_splits = False
        elif importance_type == "total_cover":
            importance_type = "cover"
            average_over_splits = False

        trees = self.get_dump(fmap, with_stats=True)

        importance_type += "="
        fmap = {}
        gmap = {}
        for tree in trees:
            for line in tree.split("\n"):
                # look for the opening square bracket
                arr = line.split("[")
                # if no opening bracket (leaf node), ignore this line
                if len(arr) == 1:
                    continue

                # look for the closing bracket, extract only info within that bracket
                fid = arr[1].split("]")

                # extract gain or cover from string after closing bracket
                g = float(fid[1].split(importance_type)[1].split(",")[0])

                # extract feature name from string before closing bracket
                fid = fid[0].split("<")[0]

                if fid not in fmap:
                    # if the feature hasn't been seen yet
                    fmap[fid] = 1
                    gmap[fid] = g
                else:
                    fmap[fid] += 1
                    gmap[fid] += g

        # calculate average value (gain/cover) for each feature
        if average_over_splits:
            for fid in gmap:
                gmap[fid] = gmap[fid] / fmap[fid]

        return gmap

    def trees_to_dataframe(self, fmap=""):
        """Parse a boosted tree model text dump into a pandas DataFrame structure.

        This feature is only defined when the decision tree model is chosen as base
        learner (`booster in {gbtree, dart}`). It is not defined for other base learner
        types, such as linear learners (`booster=gblinear`).

        Parameters
        ----------
        fmap: str (optional)
           The name of feature map file.
        """
        # pylint: disable=too-many-locals
        if not PANDAS_INSTALLED:
            raise Exception(
                (
                    "pandas must be available to use this method."
                    "Install pandas before calling again."
                )
            )

        if getattr(self, "booster", None) is not None and self.booster not in {
            "gbtree",
            "dart",
        }:
            raise ValueError(
                "This method is not defined for Booster type {}".format(self.booster)
            )

        tree_ids = []
        node_ids = []
        fids = []
        splits = []
        y_directs = []
        n_directs = []
        missings = []
        gains = []
        covers = []

        trees = self.get_dump(fmap, with_stats=True)
        for i, tree in enumerate(trees):
            for line in tree.split("\n"):
                arr = line.split("[")
                # Leaf node
                if len(arr) == 1:
                    # Last element of line.split is an empy string
                    if arr == [""]:
                        continue
                    # parse string
                    parse = arr[0].split(":")
                    stats = re.split("=|,", parse[1])

                    # append to lists
                    tree_ids.append(i)
                    node_ids.append(int(re.findall(r"\b\d+\b", parse[0])[0]))
                    fids.append("Leaf")
                    splits.append(float("NAN"))
                    y_directs.append(float("NAN"))
                    n_directs.append(float("NAN"))
                    missings.append(float("NAN"))
                    gains.append(float(stats[1]))
                    covers.append(float(stats[3]))
                # Not a Leaf Node
                else:
                    # parse string
                    fid = arr[1].split("]")
                    parse = fid[0].split("<")
                    stats = re.split("=|,", fid[1])

                    # append to lists
                    tree_ids.append(i)
                    node_ids.append(int(re.findall(r"\b\d+\b", arr[0])[0]))
                    fids.append(parse[0])
                    splits.append(float(parse[1]))
                    str_i = str(i)
                    y_directs.append(str_i + "-" + stats[1])
                    n_directs.append(str_i + "-" + stats[3])
                    missings.append(str_i + "-" + stats[5])
                    gains.append(float(stats[7]))
                    covers.append(float(stats[9]))

        ids = [str(t_id) + "-" + str(n_id) for t_id, n_id in zip(tree_ids, node_ids)]
        df = DataFrame(
            {
                "Tree": tree_ids,
                "Node": node_ids,
                "ID": ids,
                "Feature": fids,
                "Split": splits,
                "Yes": y_directs,
                "No": n_directs,
                "Missing": missings,
                "Gain": gains,
                "Cover": covers,
            }
        )

        if callable(getattr(df, "sort_values", None)):
            # pylint: disable=no-member
            return df.sort_values(["Tree", "Node"]).reset_index(drop=True)
        # pylint: disable=no-member
        return df.sort(["Tree", "Node"]).reset_index(drop=True)

    def _validate_features(self, data):
        """
        Validate Booster and data's feature_names are identical.
        Set feature_names and feature_types from DMatrix
        """
        if self.feature_names is None:
            self.feature_names = data.feature_names
            self.feature_types = data.feature_types
        else:
            # Booster can't accept data with different feature names
            if self.feature_names != data.feature_names:
                dat_missing = set(self.feature_names) - set(data.feature_names)
                my_missing = set(data.feature_names) - set(self.feature_names)

                msg = "feature_names mismatch: {0} {1}"

                if dat_missing:
                    msg += (
                        "\nexpected "
                        + ", ".join(str(s) for s in dat_missing)
                        + " in input data"
                    )

                if my_missing:
                    msg += (
                        "\ntraining data did not have the following fields: "
                        + ", ".join(str(s) for s in my_missing)
                    )

                raise ValueError(msg.format(self.feature_names, data.feature_names))

    def get_split_value_histogram(self, feature, fmap="", bins=None, as_pandas=True):
        """Get split value histogram of a feature

        Parameters
        ----------
        feature: str
            The name of the feature.
        fmap: str (optional)
            The name of feature map file.
        bin: int, default None
            The maximum number of bins.
            Number of bins equals number of unique split values n_unique,
            if bins == None or bins > n_unique.
        as_pandas: bool, default True
            Return pd.DataFrame when pandas is installed.
            If False or pandas is not installed, return numpy ndarray.

        Returns
        -------
        a histogram of used splitting values for the specified feature
        either as numpy array or pandas DataFrame.
        """
        xgdump = self.get_dump(fmap=fmap)
        values = []
        regexp = re.compile(r"\[{0}<([\d.Ee+-]+)\]".format(feature))
        for i, _ in enumerate(xgdump):
            m = re.findall(regexp, xgdump[i])
            values.extend([float(x) for x in m])

        n_unique = len(np.unique(values))
        bins = max(min(n_unique, bins) if bins is not None else n_unique, 1)

        nph = np.histogram(values, bins=bins)
        nph = np.column_stack((nph[1][1:], nph[0]))
        nph = nph[nph[:, 1] > 0]

        if as_pandas and PANDAS_INSTALLED:
            return DataFrame(nph, columns=["SplitValue", "Count"])
        if as_pandas and not PANDAS_INSTALLED:
            sys.stderr.write(
                "Returning histogram as ndarray (as_pandas == True, but pandas is not installed)."
            )
        return nph
