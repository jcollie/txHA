# -*- mode: python; coding: utf-8 -*-

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

from __future__ import absolute_import

from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import serialport
from twisted.internet import endpoints

import re
import struct
import parsley

import pkg_resources

from .. import log
from ..bitfield import BitField
from ..tbq import TokenBucketQueue

__all__ = ['InsteonAddress', 'InsteonMessageFlags', 'InsteonDevice', 'InsteonNetworkPLM', 'InsteonSerialPLM']

class InsteonAddress(object):
    insteon_address_re = re.compile('([0-9a-f]{2})\.([0-9a-f]{2})\.([0-9a-f]{2})', re.IGNORECASE)

    def __init__(self, high, middle = None, low = None):
        if isinstance(high, basestring) and middle is None and low is None:
            if len(high) == 3:
                self.high, self.middle, self.low = struct.unpack('!BBB', high)

            else:
                match = self.insteon_address_re.match(high)
                if match:
                    self.high = int(match.group(1), 16)
                    self.middle = int(match.group(2), 16)
                    self.low = int(match.group(3), 16)
                    
                else:
                    raise ValueError('not an insteon address?')
        else:
            if isinstance(high, basestring):
                if len(high) == 1:
                    self.high = struct.unpack('!B', high)[0]

                else:
                    raise ValueError('high part of address not single byte string')

            elif isinstance(high, (int, long)):
                if high >= 0 and high <= 255:
                    self.high = high

                else:
                    raise ValueError('high part of address must be in the range [0, 255]')

            else:
                raise ValueError('high part of address must be a single byte string or an integer')

            if isinstance(middle, basestring):
                if len(middle) == 1:
                    self.middle = struct.unpack('!B', middle)[0]

                else:
                    raise ValueError('middle part of address not single byte string')

            elif isinstance(middle, (int, long)):
                if middle >= 0 and middle <= 255:
                    self.middle = middle

                else:
                    raise ValueError('middle part of address must be in the range [0, 255]')

            else:
                raise ValueError('middle part of address must be a single byte string or an integer')

            if isinstance(low, basestring):
                if len(low) == 1:
                    self.low = struct.unpack('!B', low)[0]

                else:
                    raise ValueError('low part of address not single byte string')

            elif isinstance(low, (int, long)):
                if low >= 0 and  low <= 255:
                    self.low = low

                else:
                    raise ValueError('low part of address must be in the range [0, 255]')

            else:
                raise ValueError('low part of address must be a single byte string or an integer')

    @property
    def binary(self):
        return struct.pack('!BBB', self.high, self.middle, self.low)

    def __hash__(self):
        return hash(self.binary)

    def __eq__(self, other):
        return (self.high == other.high) and (self.middle == other.middle) and (self.low == other.low)

    def __ne__(self, other):
        return (self.high != other.high) or (self.middle != other.middle) or (self.low != other.low)

    def __repr__(self):
        return 'InsteonAddress(\'{:02X}.{:02X}.{:02X}\')'.format(self.high, self.middle, self.low)

class InsteonMessageFlags(BitField):
    def __init__(self, flags = 0):
        if isinstance(flags, basestring):
            flags = struct.unpack('!B', flags)[0]
        super(InsteonMessageFlags, self).__init__(flags)

    @property
    def extended(self):
        return self[4] == 1

    @extended.setter
    def extended(self, value):
        if value:
            self[4] = 1

        else:
            self[4] = 0

    @property
    def max_hops(self):
        return self[0:2]

    @max_hops.setter
    def max_hops(self, value):
        self[0:2] = value

    @property
    def hops_left(self):
        return self[2:4]

    @hops_left.setter
    def hops_left(self, value):
        self[2:4] = value

    @property
    def binary(self):
        return struct.pack('!B', int(self))

    def __repr__(self):
        return 'InsteonMessageFlags(0x{:02X})'.format(int(self))

class _InsteonDevice(object):

    @classmethod
    def get(klass, plm, address):
        if address in plm.devices:
            return plm.devices[address]
        device = klass(plm, address)
        return device

    def __init__(self, plm, address):
        self.plm = plm
        self.address = address
        self.plm.devices[address] = self
        self.expecting = None

    def processReceivedMessage(self, address_to, flags, command_1, command_2, user_data = None):
        log.debug('{}{}{}'.format(flags[7], flags[6], flags[5]))
        bgak = flags[5:8]
        if bgak == 4:
            log.debug('Broadcast Message')

        elif bgak == 0:
            log.debug('Direct Message')

        elif bgak == 1:
            log.debug('ACK of Direct Message')

        elif bgak == 5:
            log.debug('NAK of Direct Message')

        elif bgak == 6:
            log.debug('Group Broadcast Message')

        elif bgak == 2:
            log.debug('Group Cleanup Direct Message')

        elif bgak == 3:
            log.debug('ACK of Group Cleanup Direct Message')

        elif bgak == 7:
            log.debug('NAK of Group Cleanup Direct Message')

        else:
            log.debug('unkown message type: {}'.format(bgak))

        log.debug('extended: {}'.format(flags.extended))
        log.debug('hops_left: {}'.format(flags.hops_left))
        log.debug('max_hops:  {}'.format(flags.max_hops))

        if bgak == 4 and command_1 == 0x01 and command_2 == 0x00:
            self.category = address_to.high
            self.subcategory = address_to.middle
            self.firmware = address_to.low
            log.debug('category   : {:02x}'.format(address_to.high))
            log.debug('subcategory: {:02x}'.format(address_to.middle))
            log.debug('firmware   : {:02x}'.format(address_to.low))

        elif bgak == 6 and command_1 == 0x11 and command_2 == 0x00:
            log.debug('Turning on? {}'.format(address_to.low))

        elif bgak == 2 and command_1 == 0x11 and command_2 == 0x01:
            log.debug('Turning on?')

        elif bgak == 6 and command_1 == 0x13 and command_2 == 0x00:
            log.debug('Turning off? {}'.format(address_to.low))

        elif bgak == 2 and command_1 == 0x13 and command_2 == 0x01:
            log.debug('Turning off?')

        elif bgak == 1:
            if self.expecting is not None:
                if self.expecting[1] == 0x19:
                    log.debug('database delta: {}'.format(command_1))
                    log.debug('light level   : {}'.format(command_2))
                    log.debug('light level   : {}%'.format(int(round(command_2 / 255.0 * 100))))
                    self.expecting = None

        elif command_1 == 0x03 and command_2 == 0x00 and user_data is not None:
            self.category, self.subcategory, self.firmware = struct.unpack('!BBB', user_data[4:7])

            log.debug('D1              : {:02x}'.format(struct.unpack('!B', user_data[0])[0]))
            log.debug('D2-4 product key: {}'.format(`user_data[1:4]`))
            log.debug('D5   category   : {:02x}'.format(struct.unpack('!B', user_data[4])[0]))
            log.debug('D6   subcategory: {:02x}'.format(struct.unpack('!B', user_data[5])[0]))
            log.debug('D7   firmware   : {:02x}'.format(struct.unpack('!B', user_data[6])[0]))
            log.debug('D8-14           : {}'.format(`user_data[7:14]`))

def InsteonDevice(plm, address):
    return _InsteonDevice.get(plm, address)

class _InsteonBaseProtocol(object):
    def __init__(self, reactor, transport, plm):
        self.reactor = reactor
        self.plm = plm
        self.transport = transport

        self.tbq = TokenBucketQueue(self.reactor, 1.0, 1.0, start_paused = True)
        self.parser = None
        self.currentRule = 'receive'

        self.more_all_link_records = False

        self.reactor.callWhenRunning(self.start)

    def prepareParsing(self, parser):
        self.parser = parser
        self.tbq.resume()
        self.plm.ready.callback(self)

    def finishParsing(self, reason):
        log.err(reason)
        pass

    def start(self):
        self._getMessage()

    def _getMessage(self):
        d = self.tbq.get()
        d.addCallback(self._gotMessage)

    def _gotMessage(self, message):
        self.reactor.callLater(0.0, self._getMessage)
        self.transport.write(message)

    def _sendMessage(self, address, flags, command_1, command_2, user_data = None):
        if flags is None:
            flags = InsteonMessageFlags(0x0f)

        if user_data is None:
            flags.extended = False
            msg = struct.pack('!BB3scBB', 0x02, 0x62, address.binary, flags.binary, command_1, command_2)

        else:
            flags.extended = True
            if len(user_data) < 14:
                userdata += '\x00' * (14 - len(user_data))

            elif len(user_data) > 14:
                raise ValueError('user_data is too long!')

            msg = struct.pack('!BB3scBB14s', 0x02, 0x62, address.binary, flags.binary, command_1, command_2, user_data)

        self.tbq.put(msg)

    def sendGetFirstAllLinkRecord(self):
        msg = struct.pack('!BB', 0x02, 0x69)
        self.tbq.put(msg)

    def sendGetNextAllLinkRecord(self):
        msg = struct.pack('!BB', 0x02, 0x6a)
        self.tbq.put(msg)

    def sendGetProductDataRequest(self, address, flags = None):
        self._sendMessage(address, flags, 0x03, 0x00)

    def sendFxNameRequest(self, address, flags = None):
        self._sendMessage(address, flags, 0x03, 0x01)

    def sendDeviceTextStringRequest(self, address, flags = None):
        self._sendMessage(address, flags, 0x03, 0x02)

    def sendGetInsteonEngineVersion(self, address, flags = None):
        self._sendMessage(address, flags, 0x0d, 0x00)

    def sendPing(self, address, flags = None):
        self._sendMessage(address, flags, 0x0f, 0x00)

    def sendIDRequest(self, address, flags = None):
        self._sendMessage(address, flags, 0x10, 0x00)

    def sendOn(self, address, level = 0xff, flags = None):
        self._sendMessage(address, flags, 0x11, level)

    def sendOff(self, address, flags = None):
        self._sendMessage(address, flags, 0x13, 0x00)

    def sendFastOff(self, address, flags = None):
        self._sendMessage(address, flags, 0x14, 0x00)

    def sendBright(self, address, flags = None):
        self._sendMessage(address, flags, 0x15, 0x00)

    def sendDim(self, address, flags = None):
        self._sendMessage(address, flags, 0x16, 0x00)

    def sendStartManualChangeDim(self, address, flags = None):
        self._sendMessage(address, flags, 0x17, 0x00)

    def sendStartManualChangeBright(self, address, flags = None):
        self._sendMessage(address, flags, 0x17, 0x01)

    def sendStopManualChange(self, address, flags = None):
        self._sendMessage(address, flags, 0x18, 0x00)

    def sendStatusRequest(self, address, kpl_led = False, flags = None):
        if kpl_led:
            command_2 = 0x01

        else:
            command_2 = 0x00

        self._sendMessage(address, flags, 0x19, command_2)
        
    def sendGetIMInfo(self):
        msg = struct.pack('!BB', 0x02, 0x60)
        self.tbq.put(msg)

    def receive(self, *args):
        log.debug(`args`)

    def receiveMessageEcho(self, address, flags, command_1, command_2, acknak, user_data = None):
        log.debug(`('receiveMessageEcho', address, flags, command_1, command_2, acknak, user_data)`)
        if acknak and command_1 == 0x19:
            device = InsteonDevice(self.plm, address)
            device.expecting = (flags, command_1, command_2, user_data)

    def receiveMessage(self, address_from, address_to, flags, command_1, command_2, user_data = None):
        log.debug(`('receiveMessage', address_from, address_to, flags, command_1, command_2, user_data)`)
        device_from = InsteonDevice(self.plm, address_from)
        device_from.processReceivedMessage(address_to, flags, command_1, command_2, user_data)

    def receiveAllLinkRecordEcho(self, acknak):
        log.debug(`('receiveAllLinkRecordEcho', acknak)`)
        self.more_all_link_records = acknak

    def receiveAllLinkRecord(self, all_link_record_flags, all_link_group, address, link_data):
        log.debug(`('receiveAllLinkRecord', all_link_record_flags, all_link_group, address, link_data)`)
        if self.more_all_link_records:
            self.sendGetNextAllLinkRecord()

class _InsteonProtocolFactory(protocol.ClientFactory):
    insteon_grammar = pkg_resources.resource_string(__name__, 'grammar.txt')

    def __init__(self, reactor, plm):
        self.reactor = reactor
        self.plm = plm
        self.protocol = parsley.makeProtocol(self.insteon_grammar,
                                             self.senderFactory,
                                             self.receiverFactory,
                                             {'InsteonAddress': InsteonAddress,
                                              'InsteonMessageFlags': InsteonMessageFlags})

    def senderFactory(self, transport):
        base = _InsteonBaseProtocol(self.reactor, transport, self.plm)
        return base

    def receiverFactory(self, sender):
        log.debug('receiverFactory')
        return sender
    
    def buildProtocol(self, addr):
        log.debug('buildProtocol')
        return self.protocol()

class InsteonBasePLM(object):
    def __init__(self, reactor):
        self.reactor = reactor
        self.ready = defer.Deferred()
        self.ready.addCallback(self._connected)
        self.protocol = None
        self.devices = {}
        self.factory = _InsteonProtocolFactory(self.reactor, self)

    def _connected(self, protocol):
        self.protocol = protocol
        return self

    def __getattr__(self, name):
        if self.protocol is not None:
            return getattr(self.protocol, name)
        raise AttributeError

class InsteonNetworkPLM(InsteonBasePLM):
    def __init__(self, reactor, hostname, port = 9761):
        self.hostname = hostname
        self.port = port

        super(InsteonNetworkPLM, self).__init__(reactor)

        endpoint = endpoints.clientFromString(reactor, 'tcp:host={}:port={}'.format(self.hostname, self.port))
        endpoint.connect(self.factory)

class InsteonSerialPLM(object):
    def __init__(self, reactor, devicename):
        self.reactor = reactor
        self.devicename = devicename

        super(InsteonSerialPLM, self).__init__(reactor)

        serialport.SerialPort(self.factory.protocol(),
                              self.devicename,
                              self.reactor,
                              baudrate = 19200,
                              xonxoff = 0)

#t = '\x02`\x1e\xba\xfa\x037\x9c\x06'
#
#g = parsley.makeGrammar(insteon_grammar, {})
#p = g(t)
#print p.iminfo()
#checksum = (~sum(ord(x) for x in cmd) + 1) & 0xFF
