# - mode: python; coding: utf-8 -*-

# Copyright © 2013
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys

stdout_write = sys.stdout.write
stdout_flush = sys.stdout.flush
stderr_write = sys.stderr.write
stderr_flush = sys.stderr.flush

from twisted.internet import protocol
from twisted.internet import defer
from twisted.python import util
from twisted.python import failure

from twisted.python import log as _log

import re
import struct
import inspect
import traceback

EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG = range(8)
TRACE = DEBUG
INFO = INFORMATIONAL

class JournalClientProtocol(protocol.ConnectedDatagramProtocol):
    def __init__(self, reactor):
        self.reactor = reactor
        self.running = False

    def startProtocol(self):
        self.running = True

    def stopProtocol(self):
        self.running = False

    def datagramReceived(self, data):
        pass

    def write(self, data):
        if self.running:
            self.transport.write(data)

class JournalMessage(object):
    name_re = re.compile(r'[A-Z0-9][_A-Z0-9]*')
    binary_re = re.compile(r'[^\x20-\x7f]')

    converters = {'PRIORITY': lambda priority: '{:d}'.format(priority),
                  'CODE_LINE': lambda priority: '{:d}'.format(priority)}

    def __init__(self):
        self.data = b''

    def add(self, name, value):
        match = self.name_re.match(name)
        if not match:
            raise RuntimeException('bad name!')

        self.data += bytes(name)

        if name in self.converters:
            value = self.converters[name](value)

        else:
            value = value.encode('utf-8')

        match = self.binary_re.search(value)
        if match:
            self.data += '\n'
            self.data += struct.pack('<Q', len(value))
            self.data += value
            self.data += '\n'

        else:
            self.data += '='
            self.data += value
            self.data += '\n'

class JournalTransport(object):
    def __init__(self, reactor):
        self.reactor = reactor
        self.journal = JournalClientProtocol(self.reactor)
        self.reactor.connectUNIXDatagram('/run/systemd/journal/socket',
                                         self.journal)

    def send(self, event, text):
        message = JournalMessage()

        message.add('PRIORITY', event['PRIORITY'])
        
        if 'MESSAGE_ID' in event and event['MESSAGE_ID'] is not None:
            message.add('MESSAGE_ID', event['MESSAGE_ID'])

        if 'CODE_FILE' in event and event['CODE_FILE'] is not None:
            message.add('CODE_FILE', event['CODE_FILE'])

        if 'CODE_LINE' in event and event['CODE_LINE'] is not None:
            message.add('CODE_LINE', event['CODE_LINE'])

        if 'CODE_FUNC' in event and event['CODE_FUNC'] is not None:
            message.add('CODE_FUNC', event['CODE_FUNC'])

        if 'SYSLOG_IDENTIFIER' in event and event['SYSLOG_IDENTIFIER'] is not None:
            message.add('SYSLOG_IDENTIFIER', event['SYSLOG_IDENTIFIER'])

        message.add('MESSAGE', text)

        self.journal.write(message.data)

class StderrTransport(object):
    def __init__(self, reactor):
        self.reactor = reactor

    def send(self, event, text):
        global stderr_write
        global stderr_flush

        text += '\n'
        text = text.encode('utf-8')
        util.untilConcludes(stderr_write, text)
        util.untilConcludes(stderr_flush)

class Observer(object):
    def __init__(self, reactor, priority, appname = None, transports = []):
        self.reactor = reactor
        self.priority = priority
        self.appname = appname
        self.transports = transports

    def emit(self, event):
        if event.has_key('PRIORITY'):
            if event['PRIORITY'] is None:
                event['PRIORITY'] = DEBUG

            elif event['PRIORITY'] not in range(8):
                event['PRIORITY'] = DEBUG

        elif event.get('isError'):
            event['PRIORITY'] = ERROR

        else:
            event['PRIORITY'] = DEBUG

        if 'SYSLOG_IDENTIFIER' not in event and self.appname is not None:
            event['SYSLOG_IDENTIFIER'] = self.appname

        text = _log.textFromEventDict(event)
        if text is None:
            return

        text = text.rstrip()
        text = text.expandtabs()

        for transport in self.transports:
            transport.send(event, text)

        if eventDict['PRIORITY'] <= CRITICAL:
            self.reactor.stop()

def introspect(func):
    def _introspect(*args, **kw):
        if ('CODE_FILE' not in kw or
            'CODE_LINE' not in kw or
            'CODE_FUNC' not in kw):
            (kw['CODE_FILE'],
             kw['CODE_LINE'],
             kw['CODE_FUNC']) = inspect.stack()[1][1:4]
        func(*args, **kw)
    return _introspect

class Logger(object):
    def __init__(self, reactor, priority, appname, transports):
        self.reactor = reactor
        self.priority = priority
        self.appname = appname
        self.transports = transports

        self.observer = Observer(self.reactor, self.priority, self.appname, self.transports)

        _log.msg = self.msg
        _log.err = self.err
        _log.startLoggingWithObserver(self.observer.emit, setStdout = 1)

    @introspect
    def msg(self, *args, **kw):
        if 'PRIORITY' not in kw:
            kw['PRIORITY'] = DEBUG
        _log.theLogPublisher.msg(*args, **kw)

    @introspect
    def err(self, _stuff = None, _why = None, **kw):
        if _stuff is None:
            _stuff = failure.Failure()
        if isinstance(_stuff, failure.Failure):
            self.msg(failure = _stuff,
                     why = _why,
                     isError = 1,
                     **kw)
        elif isinstance(_stuff, Exception):
            self.msg(failure = failure.Failure(_stuff),
                     why = _why,
                     isError = 1,
                     **kw)
        else:
            self.msg(repr(_stuff),
                     why = _why,
                     isError = 1,
                     **kw)
     
    @introspect
    def debug(self, *args, **kw):
        kw['PRIORITY'] = DEBUG
        self.msg(*args, **kw)

    trace = debug

    @introspect
    def informational(self, *args, **kw):
        kw['PRIORITY'] = INFORMATIONAL
        self.msg(*args, **kw)

    info = informational

    @introspect
    def notice(self, *args, **kw):
        kw['PRIORITY'] = NOTICE
        self.msg(*args, **kw)

    @introspect
    def warning(self, *args, **kw):
        kw['PRIORITY'] = WARNING
        self.msg(*args, **kw)

    @introspect
    def error(self, *args, **kw):
        kw['PRIORITY'] = ERROR
        self.msg(*args, **kw)

    @introspect
    def critical(self, *args, **kw):
        kw['PRIORITY'] = CRITICAL
        self.msg(*args, **kw)

    @introspect
    def alert(self, *args, **kw):
        kw['PRIORITY'] = ALERT
        self.msg(*args, **kw)

    @introspect
    def emergency(self, *args, **kw):
        kw['PRIORITY'] = EMERGENCY
        self.msg(*args, **kw)

    @introspect
    def errback(self, failure, *args, **kw):
        if 'PRIORITY' not in kw:
            kw['PRIORITY'] = CRITICAL
        _log.err(failure, **kw)

logger = None

def setup(reactor, priority, appname):
    global logger

    if logger is not None:
        return

    logger = Logger(reactor, priority, appname, transports = [JournalTransport(reactor),
                                                              StderrTransport(reactor)])
@introspect
def msg(*args, **kw):
    if logger is None:
        util.untilConcludes(stderr_write, repr((args, kw)))
        util.untilConcludes(stderr_flush)

    else:
        logger.msg(*args, **kw)

@introspect
def err(_stuff = None, _why = None, **kw):
    if logger is None:
        util.untilConcludes(stderr_write, repr((_stuff, _why, kw)))
        util.untilConcludes(stderr_flush)

    else:
        logger.err(_stuff, _why, **kw)

@introspect
def debug(*args, **kw):
    kw['PRIORITY'] = DEBUG
    msg(*args, **kw)

trace = debug

@introspect
def informational(*args, **kw):
    kw['PRIORITY'] = INFORMATIONAL
    msg(*args, **kw)

info = informational

@introspect
def notice(*args, **kw):
    kw['PRIORITY'] = NOTICE
    msg(*args, **kw)

@introspect
def warning(*args, **kw):
    kw['PRIORITY'] = WARNING
    msg(*args, **kw)

@introspect
def error(*args, **kw):
    kw['PRIORITY'] = ERROR
    msg(*args, **kw)

@introspect
def critical(*args, **kw):
    kw['PRIORITY'] = CRITICAL
    msg(*args, **kw)

@introspect
def alert(*args, **kw):
    kw['PRIORITY'] = ALERT
    msg(*args, **kw)

@introspect
def emergency(*args, **kw):
    kw['PRIORITY'] = EMERGENCY
    msg(*args, **kw)

@introspect
def errback(failure, *args, **kw):
    if 'PRIORITY' not in kw:
        kw['PRIORITY'] = CRITICAL
    _log.err(failure, **kw)
