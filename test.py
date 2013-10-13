#!/usr/bin/python
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

from twisted.internet import reactor

from txHA import log
log.setup(reactor, log.DEBUG, 'txHA')

from txHA.insteon import InsteonDevice
from txHA.insteon import InsteonAddress
from txHA.insteon import InsteonNetworkPLM

def plm_ready(plm):
    log.debug(`plm`)
    plm.sendOff(InsteonAddress('22.b7.00'))
    plm.sendStatusRequest(InsteonAddress('22.b7.00'))

plm = InsteonNetworkPLM(reactor, '192.168.0.25')
plm.ready.addCallback(plm_ready)

reactor.run()
