from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet
from pox.lib.packet import ipv4
from collections import defaultdict

log = core.getLogger()

mac_table = {}
packet_count = defaultdict(int)
blocked_hosts = set()

THRESHOLD = 20


def _handle_PacketIn(event):

    packet = event.parsed
    if not packet:
        return

    src = packet.src
    dst = packet.dst

    mac_table[src] = event.port

    ip_packet = packet.find('ipv4')

    if ip_packet:

        src_ip = str(ip_packet.srcip)

        if src_ip == "10.0.0.3":

            packet_count[src_ip] += 1
            log.info("Traffic from %s count=%s", src_ip, packet_count[src_ip])

            if src_ip not in blocked_hosts and packet_count[src_ip] > THRESHOLD:

                log.warning("================================")
                log.warning("ALERT: Suspicious host detected")
                log.warning("Blocking host %s", src_ip)
                log.warning("================================")

                blocked_hosts.add(src_ip)

                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x0800
                msg.match.nw_src = src_ip
                msg.priority = 100
                msg.actions = []

                event.connection.send(msg)

                return

    if dst in mac_table:

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=mac_table[dst]))
        msg.in_port = event.port

        event.connection.send(msg)

    else:

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = event.port

        event.connection.send(msg)


def launch():
    log.info("Dynamic Host Blocking Controller Started")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
