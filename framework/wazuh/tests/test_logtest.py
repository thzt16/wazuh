# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from wazuh import WazuhError

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['api'] = MagicMock()
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.logtest import get_logtest_output, end_logtest_session


def send_logtest_msg_mock(arg):
    return arg


@pytest.mark.parametrize('logtest_param_values', [
    [None, 'event_value', 'log_format_value', 'location_value'],
    ['token_value', 'event_value', 'log_format_value', 'location_value'],
])
def test_get_logtest_output(logtest_param_values):
    """Test `get_logtest_output` function from module logtest.

    Parameters
    ----------
    logtest_param_values : list of str
        List of values for every kwarg.
    """
    kwargs_keys = ['token', 'event', 'log_format', 'location']
    kwargs = {key: value for key, value in zip(kwargs_keys, logtest_param_values)}
    with patch('wazuh.logtest.send_logtest_msg') as send_mock:
        send_mock.side_effect = send_logtest_msg_mock
        result = get_logtest_output(**kwargs)
        assert result
        assert result.items() <= kwargs.items()


def test_get_logtest_output_ko():
    """Test `get_logtest_output` exceptions."""
    try:
        get_logtest_output(invalid_field=None)
    except WazuhError as e:
        assert e.code == 7000


@pytest.mark.parametrize('token', [
    'thisisarandomtoken123',
    'anotherrandomtoken321'
])
def test_end_logtest_session(token):
    """Test `end_logtest_session_ko` function from module logtest.

    Parameters
    ----------
    token : str
        Logtest session token.
    """
    with patch('wazuh.logtest.send_logtest_msg') as send_mock:
        send_mock.side_effect = send_logtest_msg_mock
        result = end_logtest_session(token=token)
        assert result == {'remove_session': token}


def test_end_logtest_session_ko():
    """Test `end_logtest_session_ko` exceptions."""
    try:
        end_logtest_session()
    except WazuhError as e:
        assert e.code == 7001