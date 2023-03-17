#!/usr/bin/python3
#==============================================================================
# 5G-MAG Reference Tools: M1 Client Exceptions
#==============================================================================
#
# File: rt_m1_client/exceptions.py
# License: 5G-MAG Public License (v1.0)
# Author: David Waring
# Copyright: (C) 2023 British Broadcasting Corporation
#
# For full license terms please see the LICENSE file distributed with this
# program. If this file is missing then the license can be retrieved from
# https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
#
#==============================================================================
#
# M1 Client Exceptions
# ====================
#
# This module defines the exceptions used by the M1 client classes
#
# M1ClientError - Exception used for indicating client request issues as
#                 returned by the M1 Server (5GMS Application Function).
#
# M1ServerError - Exception used for indicating M1 server errors. The request
#                 that generated this error may succeed if retried at a later
#                 time.

'''5G-MAG Reference Tools: M1 Client Exceptions
============================================

This module defines some custom exceptions used by the M1 Client class.

The M1Error exception is the superclass of the M1ClientError and M1ServerError.
This can be used as a catch all for errors reported by the M1 Server in
response to a request.

The M1ClientError exception derives from M1Error and is used when a request
response indicates a 4XX status code. This means that there was a problem with
the request and it should not be retried without modification to correct the
issues.

The M1ServerError exception derives from M1Error and is used when a request
response indicates a 5XX status code. This means that there was an error on the
server. The request may be retried at a later time and may then succeed.
'''
from typing import Optional

from .types import ProblemDetail, InvalidParam

def format_invalid_param(inv_param: InvalidParam) -> str:
    '''
    Format an InvalidParams entry for display

    :param InvalidParam inv_param: The `InvalidParam` to generate a formatted string for.

    :return: a `str` containing the invalid parameter name optionally followed by the reason.
    :rtype: str
    '''
    ret: str = inv_param['param']
    if 'reason' in inv_param and inv_param['reason'] is not None:
        ret += ' : ' + inv_param['reason']
    return ret

class M1Error(Exception):
    '''Exception base class for all M1 Exceptions

    This can be used to catch both M1ClientError and M1ServerError exceptions.
    '''
    def __init__(self, reason: str, # pylint: disable=useless-super-delegation
                 status_code: Optional[int] = None, problem_detail: Optional[ProblemDetail] = None):
        '''Constructor

        :param str reason: The reason for the error.
        :param Optional[int] status_code: An optional HTTP status code to associate with the error.
        :param Optional[ProblemDetail] problem_detail: An optional `ProblemDetail` to associate with the error.
        '''
        super().__init__(reason, status_code, problem_detail)

    def __str__(self) -> str:
        '''String representation of the error

        :return: a formatted string representation of the `M1Error`.
        '''
        # If a ProblemDetail is available use it
        if self.args[2] is not None:
            problem = self.args[2]
            ret: str = ''
            if self.args[1] is not None:
                ret = f'[{self.args[1]}] '
            if 'title' in problem:
                ret += problem['title']+'\n'
            if 'description' in problem:
                ret += problem['description']
            if 'invalidParams' in problem and problem['invalidParams'] is not None:
                ret += '\nInvalid Parameters:\n'+'\n'.join(
                        ['  '+format_invalid_param(p) for p in problem['invalidParams']])
            return ret
        # Else if an HTTP status code is available use "[status_code] reason" as the format
        if self.args[1] is not None:
            return f'[{self.args[1]}] {self.args[0]}'
        # Otherwise just use the reason string
        return self.args[0]

    def __repr__(self) -> str:
        '''Format a `str` representation of this error

        :return: The error formatted as a constructor for this error.
        '''
        return f'{self.__class__.__name__}(reason={self.args[0]!r}, status_code={self.args[1]!r}, problem_detail={self.args[2]!r})'

class M1ClientError(M1Error):
    '''Raised when there was a client side problem during M1 operations

    This error is raised when there was a problem with the client request
    detected either by this class, or by the M1 server (5GMS Application
    Function) responding with a 4XX response.

    The request should not be repeated in this form as it will fail again.
    '''

class M1ServerError(M1Error):
    '''Raised when there was a server side problem during M1 operations

    This represents 5XX error responses from the M1 server (5GMS Application
    Function).

    The request may be repeated at a future date and may or may not work then.
    '''

__all__ = [
        "M1Error",
        "M1ClientError",
        "M1ServerError",
        ]
