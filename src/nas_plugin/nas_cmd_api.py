##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from litp.core.rpc_commands import run_rpc_command
from litp.core.litp_logging import LitpLogger
log = LitpLogger()


class NasCmdApiException(Exception):
    pass


class NasCmdApi(object):

    def __init__(self, node):
        self.agent = "nas"
        self.node = node

    def _call_mco(self, mco_action, kargs, timeout=None):
        """
        general method to run MCollective commands using run_rpc_command
        """
        log.trace.info('Running MCO NAS command {0}'.format(
            self._get_mco_nas_command(mco_action, kargs)))
        results = run_rpc_command(self.node, self.agent, mco_action, kargs,
                                                                  timeout)

        if not len(results) == 1:
            err_msg = self._gen_err_str(mco_action, kargs)
            err_msg += "Reason: Expected 1 response, received %s"\
                    % (len(results))
            log.trace.error(err_msg)
            raise NasCmdApiException(err_msg)
        if not len(results[self.node[0]]["errors"]) == 0:
            err_msg = self._gen_err_str(mco_action, kargs)
            err_msg += "Reason: MCO failure... {0}"\
                    .format(results[self.node[0]]["errors"])
            log.trace.error(err_msg)
            raise NasCmdApiException(err_msg)

        return results[self.node[0]]['data']  # we only pass in one node

    def _gen_err_str(self, action, kargs=None):
        return "Failure to execute command: {0}"\
                .format(self._get_mco_nas_command(action, kargs))

    def _get_mco_nas_command(self, action, kargs=None):
        command = "\"mco rpc {0} {1} ".format(self.agent, action)
        if kargs is not None:
            for a, v in kargs.iteritems():
                command += "{0}={1} ".format(a, v)
        command += "-I {0}\" ".format(self.node)
        return command

    def get_kwargs(self, ipv4, ipv6, export_path, mount_point):
        """
        return dict of arguements to pass to mcollective
        """
        kwargs = {"ipv4": ipv4,
                  "ipv6": ipv6,
                  "export_path": export_path,
                  "mount_point": mount_point,
                 }
        return kwargs

    def mount_ipv4(self, kargs, timeout=None):
        """
        attempt to mount over ipv4 address
        """
        mco_action = "mount_ipv4"
        result = self._call_mco(mco_action, kargs, timeout)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, kargs)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                    .format(result["retcode"], result["err"])
            raise NasCmdApiException(err_msg)

    def mount_ipv6(self, args, timeout=None):
        """
        attempt to mount over ipv6 address
        """
        mco_action = "mount_ipv6"
        result = self._call_mco(mco_action, args, timeout)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                    .format(result["retcode"], result["err"])
            raise NasCmdApiException(err_msg)

    def unmount(self, args, timeout=None):
        """
        attempt to unmount
        """
        mco_action = "unmount"
        result = self._call_mco(mco_action, args, timeout)
        if not result["retcode"] == 0:
            err_msg = self._gen_err_str(mco_action, args)
            err_msg += "Reason: Command failed... retcode {0}, stderr {1}"\
                    .format(result["retcode"], result["err"])
            raise NasCmdApiException(err_msg)
